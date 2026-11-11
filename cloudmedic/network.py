"""Formal model of AWS VPC packet reachability.

A flow (src, dst, proto, port) is evaluated hop by hop along the forward path and the return
path. Every hop is evaluated even after an earlier one fails ("full-path evaluation"), so a
single run exposes all faults on the path, including ones that an earlier fault would mask.

Semantics modelled:
  * Security groups: stateful, allow-only, rules match CIDR or a referenced security group.
  * Network ACLs: stateless, numbered rules, first match wins, implicit final deny. Traffic
    inside one subnet is not evaluated by the NACL. Return traffic must be allowed for the
    client's whole ephemeral port range; partial coverage gives intermittent failures.
  * Routing: longest-prefix match, targets local / igw- / nat- / pcx-. Peering requires an
    active connection and a return route in the peer VPC. Internet egress via an IGW needs a
    public IP on the source; via a NAT gateway the NAT's subnet needs an IGW route.
  * DNS: Route 53 private hosted zones resolve only from associated VPCs that have
    enableDnsSupport; disabling DNS support breaks all resolution in that VPC.
Not modelled: IPv6, transit gateways, load balancers, prefix lists other than the S3 gateway
endpoint, MTU/fragmentation, OS firewalls.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .checks import FAIL, PARTIAL, PASS, SKIP, Check, Result, finish

NAT_EPHEMERAL = (1024, 65535)
DEFAULT_EPHEMERAL = (32768, 60999)  # Linux default


@dataclass
class Endpoint:
    kind: str  # vpc | external | managed
    id: str
    ip: str
    public_ip: str | None = None
    subnet: str | None = None
    vpc: str | None = None
    sgs: list = field(default_factory=list)
    listening: list = field(default_factory=list)
    ephemeral: tuple = DEFAULT_EPHEMERAL
    compute_kind: str | None = None


def ip_in(ip: str, cidr: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)


def proto_match(rule_proto: str, proto: str) -> bool:
    return rule_proto in ("-1", "all") or rule_proto == proto


def port_match(rule: dict, port: int) -> bool:
    if rule.get("proto") in ("-1", "all"):
        return True
    return rule["from"] <= port <= rule["to"]


def endpoint(snap: dict, ref: str) -> Endpoint | None:
    if ref in snap.get("compute", {}):
        c = snap["compute"][ref]
        sub = c.get("subnet")
        vpc = snap["subnets"][sub]["vpc"] if sub and sub in snap["subnets"] else None
        return Endpoint(
            kind="vpc" if sub else "managed", id=ref, ip=c.get("private_ip") or "0.0.0.0",
            public_ip=c.get("public_ip"), subnet=sub, vpc=vpc, sgs=list(c.get("security_groups", [])),
            listening=c.get("listening", []) if "listening" in c else [], ephemeral=tuple(c.get("ephemeral", DEFAULT_EPHEMERAL)),
            compute_kind=c.get("kind"),
        )
    if ref in snap.get("external_hosts", {}):
        h = snap["external_hosts"][ref]
        return Endpoint(kind="external", id=ref, ip=h["ip"], public_ip=h["ip"], listening=h.get("listening", []),
                        ephemeral=tuple(h.get("ephemeral", DEFAULT_EPHEMERAL)))
    return None


def endpoint_by_ip(snap: dict, ip: str) -> Endpoint | None:
    for cid, c in snap.get("compute", {}).items():
        if c.get("private_ip") == ip:
            return endpoint(snap, cid)
    for hid, h in snap.get("external_hosts", {}).items():
        if h["ip"] == ip:
            return endpoint(snap, hid)
    return None


# ---------------------------------------------------------------- primitives

def sg_allows(snap: dict, sg_ids: list, direction: str, proto: str, port: int, peer_ip: str, peer_sgs: list):
    for sg_id in sg_ids:
        sg = snap["security_groups"].get(sg_id)
        if not sg:
            continue
        for i, r in enumerate(sg.get(direction, [])):
            if not proto_match(r["proto"], proto) or not port_match(r, port):
                continue
            if ("cidr" in r and ip_in(peer_ip, r["cidr"])) or ("sg" in r and r["sg"] in peer_sgs):
                return True, (sg_id, i)
    return False, None


def nacl_decision(nacl: dict, direction: str, proto: str, port: int, ip: str):
    for r in sorted(nacl.get(direction, []), key=lambda r: r["rule"]):
        if proto_match(r["proto"], proto) and port_match(r, port) and ip_in(ip, r["cidr"]):
            return r["action"] == "allow", r
    return False, None  # implicit deny (rule *)


def nacl_range(nacl: dict, direction: str, proto: str, lo: int, hi: int, ip: str):
    """Fraction of ports in [lo, hi] allowed, plus the first rule that blocks a port (or None)."""
    cuts = {lo, hi + 1}
    for r in nacl.get(direction, []):
        if r.get("proto") in ("-1", "all"):
            continue
        for b in (r["from"], r["to"] + 1):
            if lo < b <= hi:
                cuts.add(b)
    cuts = sorted(cuts)
    allowed, blocker = 0, None
    for a, b in zip(cuts, cuts[1:]):
        ok, rule = nacl_decision(nacl, direction, proto, a, ip)
        if ok:
            allowed += b - a
        elif blocker is None:
            blocker = rule
    return allowed / (hi - lo + 1), blocker


def route_lookup(rt: dict, ip: str):
    best, best_len = None, -1
    for r in rt.get("routes", []):
        try:
            net = ipaddress.ip_network(r["dest"], strict=False)
        except ValueError:
            continue  # prefix-list destinations (gateway endpoints)
        if ipaddress.ip_address(ip) in net and net.prefixlen > best_len:
            best, best_len = r, net.prefixlen
    return best


# ---------------------------------------------------------------- check builders

def _sg_check(snap, cid, ep_sgs, direction, proto, port, peer_ip, peer_sgs, fault, peer_id, owner):
    ok, hit = sg_allows(snap, ep_sgs, direction, proto, port, peer_ip, peer_sgs)
    sg = ep_sgs[0] if ep_sgs else None
    word = "egress to" if direction == "egress" else "ingress from"
    ctx = {"direction": direction, "proto": proto, "port": port, "peer_ip": peer_ip,
           "peer_sgs": peer_sgs, "peer": peer_id, "owner": owner, "sgs": ep_sgs}
    if ok:
        return Check(cid, "security_group", hit[0], PASS, f"{hit[0]} allows {proto}/{port} {word} {peer_ip}",
                     None, {**ctx, "sg": hit[0], "rule_index": hit[1]})
    return Check(cid, "security_group", sg, FAIL,
                 f"no rule in {', '.join(ep_sgs) or '(none)'} allows {proto}/{port} {word} {peer_ip}", fault, ctx)


def _nacl_check(snap, cid, subnet_id, direction, proto, port, peer_ip, fault):
    nacl_id = snap["subnets"][subnet_id]["nacl"]
    nacl = snap["nacls"].get(nacl_id, {})
    ok, rule = nacl_decision(nacl, direction, proto, port, peer_ip)
    if ok:
        return Check(cid, "nacl", nacl_id, PASS, f"{nacl_id} rule {rule['rule']} allows {direction} {proto}/{port} {peer_ip}",
                     None, {"direction": direction, "proto": proto, "lo": port, "hi": port, "peer_ip": peer_ip,
                            "rule": rule["rule"], "subnet": subnet_id})
    why = f"rule {rule['rule']} denies" if rule else "no rule matches (implicit deny)"
    return Check(cid, "nacl", nacl_id, FAIL, f"{nacl_id} {direction} {proto}/{port} {peer_ip}: {why}", fault,
                 {"direction": direction, "proto": proto, "lo": port, "hi": port, "peer_ip": peer_ip,
                  "deny_rule": rule["rule"] if rule else None, "subnet": subnet_id})


def _nacl_return_check(snap, cid, subnet_id, direction, proto, eph, peer_ip):
    nacl_id = snap["subnets"][subnet_id]["nacl"]
    nacl = snap["nacls"].get(nacl_id, {})
    frac, blocker = nacl_range(nacl, direction, proto, eph[0], eph[1], peer_ip)
    rng = f"{eph[0]}-{eph[1]}"
    if frac >= 1.0:
        return Check(cid, "nacl", nacl_id, PASS, f"{nacl_id} allows return traffic {direction} {proto}/{rng} {peer_ip}",
                     None, {"direction": direction, "proto": proto, "lo": eph[0], "hi": eph[1], "peer_ip": peer_ip,
                            "subnet": subnet_id})
    status = PARTIAL if frac > 0 else FAIL
    why = f"rule {blocker['rule']} denies part of it" if blocker else "implicit deny"
    return Check(cid, "nacl", nacl_id, status,
                 f"{nacl_id} allows only {frac:.0%} of return ports {direction} {proto}/{rng} {peer_ip} ({why})",
                 "nacl_return_block",
                 {"direction": direction, "proto": proto, "lo": eph[0], "hi": eph[1], "peer_ip": peer_ip,
                  "deny_rule": blocker["rule"] if blocker else None, "subnet": subnet_id, "coverage": frac})


def _listen_check(D: Endpoint, proto, port):
    if D.listening is None:  # imported from a live account: we cannot see host processes
        return Check("dst_listening", "host", D.id, SKIP, f"listening state of {D.id} is unknown (imported snapshot)")
    ok = any(l["proto"] == proto and l["port"] == port for l in D.listening)
    if ok:
        return Check("dst_listening", "host", D.id, PASS, f"{D.id} listens on {proto}/{port}")
    return Check("dst_listening", "host", D.id, FAIL, f"nothing listens on {proto}/{port} at {D.id}",
                 "service_not_listening", {"proto": proto, "port": port})


def _igw_for_vpc(snap, igw_id, vpc):
    igw = snap["internet_gateways"].get(igw_id)
    return igw is not None and igw.get("vpc") == vpc


# ---------------------------------------------------------------- DNS

def resolve(snap: dict, S: Endpoint, name: str):
    vpc_dns = snap["vpcs"][S.vpc].get("enable_dns_support", True) if S.vpc else True
    for zid, z in snap.get("private_zones", {}).items():
        if name in z.get("records", {}):
            ip = z["records"][name]
            D = endpoint_by_ip(snap, ip) or Endpoint(kind="vpc", id=name, ip=ip)
            if S.kind == "vpc" and not vpc_dns:
                return D, Check("dns_resolution", "dns", S.vpc, FAIL,
                                f"{S.vpc} has enableDnsSupport=false; the Amazon DNS resolver is unavailable",
                                "dns_support_disabled", {"vpc": S.vpc, "name": name})
            if S.kind == "vpc" and S.vpc in z.get("vpcs", []):
                return D, Check("dns_resolution", "dns", zid, PASS, f"{name} -> {ip} via private zone {z['name']}")
            return D, Check("dns_resolution", "dns", zid, FAIL,
                            f"private zone {z['name']} ({zid}) is not associated with {S.vpc}; {name} does not resolve",
                            "dns_phz_not_associated", {"zone": zid, "vpc": S.vpc, "name": name})
    for hid, h in snap.get("external_hosts", {}).items():
        if h.get("hostname") == name:
            D = endpoint(snap, hid)
            if S.kind == "vpc" and not vpc_dns:
                return D, Check("dns_resolution", "dns", S.vpc, FAIL,
                                f"{S.vpc} has enableDnsSupport=false; {name} cannot be resolved",
                                "dns_support_disabled", {"vpc": S.vpc, "name": name})
            return D, Check("dns_resolution", "dns", None, PASS, f"{name} -> {h['ip']} (public DNS)")
    return None, Check("dns_resolution", "dns", None, FAIL, f"{name} is not a known name (NXDOMAIN)", None, {"name": name})


# ---------------------------------------------------------------- evaluation

SYMPTOMS = {
    "dns_resolution": "dns_failure",
    "dst_listening": "connection_refused",
}


def _symptom(check: Check) -> str:
    if check.id in SYMPTOMS:
        return SYMPTOMS[check.id]
    if check.status == PARTIAL:
        return "intermittent_timeout"
    return "timeout"


def evaluate_flow(snap: dict, src: str, dst: str, proto: str = "tcp", port: int = 443,
                  ignore_listening: bool = False) -> Result:
    S = endpoint(snap, src)
    if S is None:
        return Result(False, [Check("src", "inventory", src, FAIL, f"unknown source {src}")], "unknown_endpoint")
    checks: list[Check] = []
    D = endpoint(snap, dst)
    if D is None:
        D, dns = resolve(snap, S, dst)
        checks.append(dns)
        if D is None:
            return finish(checks, _symptom)

    if S.kind == "managed":
        if D.kind == "external":
            checks.append(Check("managed_network", "routing", S.id, PASS, f"{S.id} runs outside a VPC and has internet access"))
            if not ignore_listening:
                checks.append(_listen_check(D, proto, port))
            return finish(checks, _symptom)
        if D.kind == "vpc" and not D.public_ip:
            checks.append(Check("managed_network", "routing", S.id, FAIL,
                                f"{S.id} is not attached to a VPC and cannot reach private address {D.ip}",
                                "lambda_not_in_vpc", {"dst": D.id}))
            return finish(checks, _symptom)
        S = Endpoint(kind="external", id=S.id, ip="3.80.0.10", public_ip="3.80.0.10", ephemeral=NAT_EPHEMERAL)

    if S.kind == "vpc" and D.kind == "vpc":
        _vpc_to_vpc(snap, S, D, proto, port, ignore_listening, checks)
    elif S.kind == "vpc" and D.kind == "external":
        _vpc_to_internet(snap, S, D, proto, port, ignore_listening, checks)
    elif S.kind == "external" and D.kind == "vpc":
        _internet_to_vpc(snap, S, D, proto, port, ignore_listening, checks)
    else:
        checks.append(Check("path", "routing", None, SKIP, "external-to-external flow is out of scope"))
    return finish(checks, _symptom)


def _vpc_to_vpc(snap, S, D, proto, port, ignore_listening, checks):
    same_subnet = S.subnet == D.subnet
    checks.append(_sg_check(snap, "src_sg_egress", S.sgs, "egress", proto, port, D.ip, D.sgs, "sg_egress_block", D.id, S.id))
    if not same_subnet:
        checks.append(_nacl_check(snap, "src_nacl_egress", S.subnet, "egress", proto, port, D.ip, "nacl_egress_block"))
    s_rt_id = snap["subnets"][S.subnet]["route_table"]
    if S.vpc == D.vpc:
        checks.append(Check("route", "routing", s_rt_id, PASS, f"{D.ip} is inside {S.vpc} (local route)"))
    else:
        _peering_routes(snap, S, D, s_rt_id, checks)
    if not same_subnet and D.subnet:
        checks.append(_nacl_check(snap, "dst_nacl_ingress", D.subnet, "ingress", proto, port, S.ip, "nacl_ingress_block"))
    checks.append(_sg_check(snap, "dst_sg_ingress", D.sgs, "ingress", proto, port, S.ip, S.sgs, "sg_ingress_block", S.id, D.id))
    if not ignore_listening:
        checks.append(_listen_check(D, proto, port))
    if not same_subnet and D.subnet:
        checks.append(_nacl_return_check(snap, "return_dst_nacl_egress", D.subnet, "egress", proto, S.ephemeral, S.ip))
        checks.append(_nacl_return_check(snap, "return_src_nacl_ingress", S.subnet, "ingress", proto, S.ephemeral, D.ip))


def _peering_routes(snap, S, D, s_rt_id, checks):
    def pcx_between(r):
        if not r or not str(r["target"]).startswith("pcx-"):
            return None
        p = snap.get("vpc_peerings", {}).get(r["target"])
        if p and {p["requester_vpc"], p["accepter_vpc"]} == {S.vpc, D.vpc}:
            return r["target"]
        return None

    d_rt_id = snap["subnets"][D.subnet]["route_table"]
    peerings = [k for k, p in snap.get("vpc_peerings", {}).items()
                if {p["requester_vpc"], p["accepter_vpc"]} == {S.vpc, D.vpc}]
    fwd = pcx_between(route_lookup(snap["route_tables"][s_rt_id], D.ip))
    ctx_f = {"dest_ip": D.ip, "dest_subnet_cidr": snap["subnets"][D.subnet]["cidr"],
             "dest_vpc_cidr": snap["vpcs"][D.vpc]["cidr"], "pcx": peerings[0] if peerings else None}
    if fwd:
        checks.append(Check("route", "routing", s_rt_id, PASS, f"{s_rt_id} routes {D.ip} to {fwd}", None,
                            {**ctx_f, "dest": route_lookup(snap["route_tables"][s_rt_id], D.ip)["dest"]}))
    else:
        checks.append(Check("route", "routing", s_rt_id, FAIL,
                            f"{s_rt_id} has no route to {D.ip} through a peering with {D.vpc}",
                            "peering_route_missing", ctx_f))
    pcx = fwd or (peerings[0] if peerings else None)
    if pcx:
        st = snap["vpc_peerings"][pcx]["status"]
        checks.append(Check("peering_status", "routing", pcx, PASS if st == "active" else FAIL,
                            f"peering {pcx} is {st}", None if st == "active" else "peering_not_active", {}))
    else:
        checks.append(Check("peering_status", "routing", None, FAIL, f"no peering connection between {S.vpc} and {D.vpc}",
                            "peering_missing", {}))
    back = pcx_between(route_lookup(snap["route_tables"][d_rt_id], S.ip))
    ctx_b = {"dest_ip": S.ip, "dest_subnet_cidr": snap["subnets"][S.subnet]["cidr"],
             "dest_vpc_cidr": snap["vpcs"][S.vpc]["cidr"], "pcx": pcx}
    if back:
        checks.append(Check("return_route", "routing", d_rt_id, PASS, f"{d_rt_id} routes return traffic to {S.ip} via {back}", None,
                            {**ctx_b, "dest": route_lookup(snap["route_tables"][d_rt_id], S.ip)["dest"]}))
    else:
        checks.append(Check("return_route", "routing", d_rt_id, FAIL,
                            f"{d_rt_id} (peer side) has no route back to {S.ip} through the peering",
                            "peering_route_missing", ctx_b))


def _vpc_to_internet(snap, S, D, proto, port, ignore_listening, checks):
    checks.append(_sg_check(snap, "src_sg_egress", S.sgs, "egress", proto, port, D.ip, [], "sg_egress_block", D.id, S.id))
    checks.append(_nacl_check(snap, "src_nacl_egress", S.subnet, "egress", proto, port, D.ip, "nacl_egress_block"))
    s_rt_id = snap["subnets"][S.subnet]["route_table"]
    r = route_lookup(snap["route_tables"][s_rt_id], D.ip)
    target = str(r["target"]) if r else None
    ctx = {"dest_ip": D.ip, "vpc": S.vpc, "subnet": S.subnet}
    rctx = {**ctx, "dest": r["dest"] if r else None, "target": target, "rt": s_rt_id}
    if target and target.startswith("igw-"):
        checks.append(Check("route", "routing", s_rt_id, PASS, f"{s_rt_id} sends {D.ip} to {target}", None, rctx))
        _igw_attached_check(snap, target, S.vpc, checks)
        if S.public_ip and S.compute_kind != "lambda":
            checks.append(Check("src_public_ip", "addressing", S.id, PASS, f"{S.id} has public IP {S.public_ip}"))
        elif S.compute_kind == "lambda":
            checks.append(Check("src_public_ip", "addressing", S.id, FAIL,
                                f"{S.id} is a Lambda function in a subnet routed to an internet gateway; Lambda ENIs never "
                                "get public IPs, so it needs a private subnet with a NAT gateway",
                                "lambda_public_subnet", ctx))
        else:
            checks.append(Check("src_public_ip", "addressing", S.id, FAIL,
                                f"{S.id} has no public IP, so traffic through {target} cannot be translated",
                                "no_public_ip", ctx))
        nat_subnet = None
    elif target and target.startswith("nat-"):
        checks.append(Check("route", "routing", s_rt_id, PASS, f"{s_rt_id} sends {D.ip} to {target}", None, rctx))
        nat = snap["nat_gateways"].get(target)
        nat_subnet = nat["subnet"] if nat else None
        if nat is None:
            checks[-1] = Check("route", "routing", s_rt_id, FAIL, f"{s_rt_id} routes to {target}, which does not exist (blackhole)",
                               "route_missing_internet", ctx)
        else:
            n_rt_id = snap["subnets"][nat_subnet]["route_table"]
            nr = route_lookup(snap["route_tables"][n_rt_id], D.ip)
            if nr and str(nr["target"]).startswith("igw-"):
                checks.append(Check("nat_subnet_route", "routing", n_rt_id, PASS, f"NAT {target} egresses via {nr['target']}"))
                _igw_attached_check(snap, nr["target"], S.vpc, checks)
            else:
                checks.append(Check("nat_subnet_route", "routing", target, FAIL,
                                    f"NAT gateway {target} sits in {nat_subnet}, whose route table {n_rt_id} has no route to an "
                                    "internet gateway (NAT gateway placed in a private subnet)",
                                    "nat_misplaced", {"nat": target, "nat_subnet": nat_subnet, "rt": n_rt_id, "vpc": S.vpc}))
            if nat_subnet != S.subnet:
                checks.append(_nacl_check(snap, "nat_nacl_ingress", nat_subnet, "ingress", proto, port, S.ip, "nacl_ingress_block"))
                checks.append(_nacl_check(snap, "nat_nacl_egress", nat_subnet, "egress", proto, port, D.ip, "nacl_egress_block"))
                checks.append(_nacl_return_check(snap, "return_nat_nacl_ingress", nat_subnet, "ingress", proto, NAT_EPHEMERAL, D.ip))
                checks.append(_nacl_return_check(snap, "return_nat_nacl_egress", nat_subnet, "egress", proto, S.ephemeral, S.ip))
    else:
        why = f"routes it to {target}" if target else "has no route"
        checks.append(Check("route", "routing", s_rt_id, FAIL, f"{s_rt_id} {why} for internet destination {D.ip}",
                            "route_missing_internet", ctx))
        _vpc_igw_check(snap, S.vpc, checks)
        nat_subnet = None
    if not ignore_listening:
        checks.append(_listen_check(D, proto, port))
    checks.append(_nacl_return_check(snap, "return_src_nacl_ingress", S.subnet, "ingress", proto, S.ephemeral, D.ip))


def _igw_attached_check(snap, igw_id, vpc, checks):
    if _igw_for_vpc(snap, igw_id, vpc):
        checks.append(Check("igw_attached", "routing", igw_id, PASS, f"{igw_id} is attached to {vpc}"))
    else:
        checks.append(Check("igw_attached", "routing", igw_id, FAIL, f"{igw_id} is not attached to {vpc}",
                            "igw_detached", {"igw": igw_id, "vpc": vpc}))


def _vpc_igw_check(snap, vpc, checks):
    """With no usable default route we cannot follow the path, but an internet path also needs an
    attached IGW; checking it here keeps a detached gateway visible behind a missing route."""
    if any(g.get("vpc") == vpc for g in snap["internet_gateways"].values()):
        return
    detached = next((k for k, g in snap["internet_gateways"].items() if not g.get("vpc")), None)
    checks.append(Check("igw_attached", "routing", detached, FAIL,
                        f"{vpc} has no attached internet gateway" + (f" ({detached} exists but is detached)" if detached else ""),
                        "igw_detached", {"igw": detached, "vpc": vpc}))


def _internet_to_vpc(snap, S, D, proto, port, ignore_listening, checks):
    ctx = {"vpc": D.vpc, "subnet": D.subnet}
    if D.public_ip:
        checks.append(Check("dst_public_ip", "addressing", D.id, PASS, f"{D.id} has public IP {D.public_ip}"))
    else:
        checks.append(Check("dst_public_ip", "addressing", D.id, FAIL, f"{D.id} has no public IP and cannot be reached from the internet",
                            "no_public_ip", ctx))
    d_rt_id = snap["subnets"][D.subnet]["route_table"]
    r = route_lookup(snap["route_tables"][d_rt_id], S.ip)
    if r and str(r["target"]).startswith("igw-"):
        checks.append(Check("dst_igw_route", "routing", d_rt_id, PASS, f"{d_rt_id} routes replies to {S.ip} via {r['target']}",
                            None, {**ctx, "dest": r["dest"], "target": r["target"], "rt": d_rt_id}))
        _igw_attached_check(snap, r["target"], D.vpc, checks)
    else:
        checks.append(Check("dst_igw_route", "routing", d_rt_id, FAIL,
                            f"{d_rt_id} has no internet-gateway route, so replies to {S.ip} cannot leave the VPC",
                            "route_missing_internet", {**ctx, "dest_ip": S.ip}))
        _vpc_igw_check(snap, D.vpc, checks)
    checks.append(_nacl_check(snap, "dst_nacl_ingress", D.subnet, "ingress", proto, port, S.ip, "nacl_ingress_block"))
    checks.append(_sg_check(snap, "dst_sg_ingress", D.sgs, "ingress", proto, port, S.ip, [], "sg_ingress_block", S.id, D.id))
    if not ignore_listening:
        checks.append(_listen_check(D, proto, port))
    checks.append(_nacl_return_check(snap, "return_dst_nacl_egress", D.subnet, "egress", proto, S.ephemeral, S.ip))
