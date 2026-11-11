"""Build a CloudMedic snapshot from a live AWS account using read-only Describe/Get/List calls.

Needs credentials with read-only access (the AWS managed policy `ReadOnlyAccess`, or
`SecurityAudit` + `ViewOnlyAccess`). No resource is created or modified, and these API calls
are free. Host listening state cannot be observed from the control plane, so imported compute
has `listening: null` and the listening check is skipped.

    python -m cloudmedic.aws.importer --profile cloudmedic --region us-east-1 --out snapshot.json
"""
from __future__ import annotations

import argparse
import json
import urllib.parse

PROTO = {"-1": "-1", "6": "tcp", "17": "udp", "1": "icmp", "tcp": "tcp", "udp": "udp", "icmp": "icmp"}


def _name(tags, default):
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value") or default
    return default


def _paginate(client, op, key, **kw):
    for page in client.get_paginator(op).paginate(**kw):
        yield from page.get(key, [])


def _sg_rules(perms, egress=False):
    out = []
    for p in perms:
        proto = PROTO.get(str(p.get("IpProtocol")), str(p.get("IpProtocol")))
        lo, hi = (0, 65535) if proto == "-1" else (p.get("FromPort", 0), p.get("ToPort", 65535))
        for r in p.get("IpRanges", []):
            out.append({"proto": proto, "from": lo, "to": hi, "cidr": r["CidrIp"]})
        for g in p.get("UserIdGroupPairs", []):
            out.append({"proto": proto, "from": lo, "to": hi, "sg": g["GroupId"]})
    return out


def import_account(session, include_iam: bool = True) -> dict:
    ec2 = session.client("ec2")
    sts = session.client("sts")
    account = sts.get_caller_identity()["Account"]
    snap = {"account_id": account, "region": session.region_name, "vpcs": {}, "subnets": {}, "route_tables": {},
            "internet_gateways": {}, "nat_gateways": {}, "vpc_peerings": {}, "vpc_endpoints": {}, "security_groups": {},
            "nacls": {}, "compute": {}, "external_hosts": {}, "private_zones": {}, "iam": {"roles": {}, "policies": {}},
            "organizations": {"scps": {}, "accounts": {}}, "resources": {}}

    for v in _paginate(ec2, "describe_vpcs", "Vpcs"):
        attrs = {a: ec2.describe_vpc_attribute(VpcId=v["VpcId"], Attribute=a) for a in ("enableDnsSupport", "enableDnsHostnames")}
        snap["vpcs"][v["VpcId"]] = {"name": _name(v.get("Tags"), v["VpcId"]), "cidr": v["CidrBlock"],
                                   "enable_dns_support": attrs["enableDnsSupport"]["EnableDnsSupport"]["Value"],
                                   "enable_dns_hostnames": attrs["enableDnsHostnames"]["EnableDnsHostnames"]["Value"]}
    main_rt, assoc_rt = {}, {}
    for rt in _paginate(ec2, "describe_route_tables", "RouteTables"):
        routes = []
        for r in rt.get("Routes", []):
            dest = r.get("DestinationCidrBlock")
            if not dest or r.get("State") == "blackhole":
                continue
            target = (r.get("GatewayId") if r.get("GatewayId") != "local" else "local") or r.get("NatGatewayId") or \
                r.get("VpcPeeringConnectionId") or r.get("TransitGatewayId") or r.get("NetworkInterfaceId")
            routes.append({"dest": dest, "target": target})
        snap["route_tables"][rt["RouteTableId"]] = {"name": _name(rt.get("Tags"), rt["RouteTableId"]), "vpc": rt["VpcId"], "routes": routes}
        for a in rt.get("Associations", []):
            if a.get("Main"):
                main_rt[rt["VpcId"]] = rt["RouteTableId"]
            elif a.get("SubnetId"):
                assoc_rt[a["SubnetId"]] = rt["RouteTableId"]
    nacl_of = {}
    for n in _paginate(ec2, "describe_network_acls", "NetworkAcls"):
        rules = {"ingress": [], "egress": []}
        for e in n.get("Entries", []):
            if e["RuleNumber"] == 32767 or "CidrBlock" not in e:
                continue
            proto = PROTO.get(str(e["Protocol"]), str(e["Protocol"]))
            pr = e.get("PortRange") or {}
            rules["egress" if e["Egress"] else "ingress"].append({
                "rule": e["RuleNumber"], "proto": proto, "from": pr.get("From", 0), "to": pr.get("To", 65535),
                "cidr": e["CidrBlock"], "action": e["RuleAction"]})
        snap["nacls"][n["NetworkAclId"]] = {"name": _name(n.get("Tags"), n["NetworkAclId"]), "vpc": n["VpcId"], **rules}
        for a in n.get("Associations", []):
            nacl_of[a["SubnetId"]] = n["NetworkAclId"]
    for s in _paginate(ec2, "describe_subnets", "Subnets"):
        snap["subnets"][s["SubnetId"]] = {"name": _name(s.get("Tags"), s["SubnetId"]), "vpc": s["VpcId"], "cidr": s["CidrBlock"],
                                         "route_table": assoc_rt.get(s["SubnetId"], main_rt.get(s["VpcId"])),
                                         "nacl": nacl_of.get(s["SubnetId"])}
    for g in _paginate(ec2, "describe_internet_gateways", "InternetGateways"):
        att = [a["VpcId"] for a in g.get("Attachments", []) if a.get("State") in ("available", "attached")]
        snap["internet_gateways"][g["InternetGatewayId"]] = {"name": _name(g.get("Tags"), g["InternetGatewayId"]), "vpc": att[0] if att else None}
    for n in _paginate(ec2, "describe_nat_gateways", "NatGateways"):
        if n["State"] in ("available", "pending"):
            snap["nat_gateways"][n["NatGatewayId"]] = {"name": _name(n.get("Tags"), n["NatGatewayId"]), "subnet": n["SubnetId"],
                                                      "public_ip": (n.get("NatGatewayAddresses") or [{}])[0].get("PublicIp")}
    for p in _paginate(ec2, "describe_vpc_peering_connections", "VpcPeeringConnections"):
        snap["vpc_peerings"][p["VpcPeeringConnectionId"]] = {
            "name": _name(p.get("Tags"), p["VpcPeeringConnectionId"]), "requester_vpc": p["RequesterVpcInfo"].get("VpcId"),
            "accepter_vpc": p["AccepterVpcInfo"].get("VpcId"), "status": p["Status"]["Code"]}
    for e in _paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
        snap["vpc_endpoints"][e["VpcEndpointId"]] = {"name": _name(e.get("Tags"), e["VpcEndpointId"]), "vpc": e["VpcId"],
                                                    "service": e["ServiceName"].split(".")[-1], "route_tables": e.get("RouteTableIds", []),
                                                    "policy": json.loads(e["PolicyDocument"]) if e.get("PolicyDocument") else None}
    for g in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
        snap["security_groups"][g["GroupId"]] = {"name": g["GroupName"], "vpc": g.get("VpcId"),
                                                "ingress": _sg_rules(g.get("IpPermissions", [])),
                                                "egress": _sg_rules(g.get("IpPermissionsEgress", []), True)}
    profiles = {}
    for r in _paginate(ec2, "describe_instances", "Reservations"):
        for i in r["Instances"]:
            if i["State"]["Name"] not in ("running", "stopped", "pending"):
                continue
            prof = (i.get("IamInstanceProfile") or {}).get("Arn")
            snap["compute"][i["InstanceId"]] = {
                "name": _name(i.get("Tags"), i["InstanceId"]), "kind": "ec2", "subnet": i.get("SubnetId"),
                "private_ip": i.get("PrivateIpAddress"), "public_ip": i.get("PublicIpAddress"),
                "security_groups": [g["GroupId"] for g in i.get("SecurityGroups", [])], "role": None, "listening": None,
                "ephemeral": [32768, 60999] if i.get("Platform") != "windows" else [49152, 65535]}
            if prof:
                profiles[i["InstanceId"]] = prof.split("/")[-1]
    lam = session.client("lambda")
    for f in _paginate(lam, "list_functions", "Functions"):
        vc = f.get("VpcConfig") or {}
        subnets = vc.get("SubnetIds") or []
        role_name = f["Role"].split("/")[-1]
        snap["compute"][f"fn-{f['FunctionName']}"] = {
            "name": f["FunctionName"], "kind": "lambda", "subnet": subnets[0] if subnets else None,
            "private_ip": None, "public_ip": None, "security_groups": vc.get("SecurityGroupIds", []),
            "role": f"role-{role_name}", "listening": [], "ephemeral": [1024, 65535]}
    rds = session.client("rds")
    for d in _paginate(rds, "describe_db_instances", "DBInstances"):
        sub = (d.get("DBSubnetGroup") or {}).get("Subnets", [{}])[0].get("SubnetIdentifier")
        snap["compute"][f"db-{d['DBInstanceIdentifier']}"] = {
            "name": d["DBInstanceIdentifier"], "kind": "rds", "subnet": sub, "private_ip": None,
            "public_ip": "rds-public" if d.get("PubliclyAccessible") else None,
            "security_groups": [g["VpcSecurityGroupId"] for g in d.get("VpcSecurityGroups", [])],
            "role": None, "listening": [{"proto": "tcp", "port": d.get("Endpoint", {}).get("Port", 5432)}], "ephemeral": [32768, 60999]}
    _fill_private_ips(snap)
    r53 = session.client("route53")
    for z in _paginate(r53, "list_hosted_zones", "HostedZones"):
        if not z.get("Config", {}).get("PrivateZone"):
            continue
        zid = z["Id"].split("/")[-1]
        info = r53.get_hosted_zone(Id=zid)
        recs = {}
        for rr in _paginate(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zid):
            if rr["Type"] == "A" and rr.get("ResourceRecords"):
                recs[rr["Name"].rstrip(".")] = rr["ResourceRecords"][0]["Value"]
        snap["private_zones"][zid] = {"name": z["Name"].rstrip("."), "vpcs": [v["VPCId"] for v in info.get("VPCs", [])], "records": recs}
    if include_iam:
        _import_iam(session, snap, profiles)
    return snap


def _fill_private_ips(snap):
    """Lambda and RDS ENIs: use a stable address inside the subnet so flows can be evaluated."""
    import ipaddress
    for k, c in snap["compute"].items():
        if c.get("private_ip") or not c.get("subnet") or c["subnet"] not in snap["subnets"]:
            continue
        net = ipaddress.ip_network(snap["subnets"][c["subnet"]]["cidr"])
        c["private_ip"] = str(net.network_address + 200 + (sum(map(ord, k)) % 40))


def _doc(raw):
    if isinstance(raw, str):
        return json.loads(urllib.parse.unquote(raw))
    return raw


def _import_iam(session, snap, profiles):
    iam = session.client("iam")
    acct = snap["account_id"]
    needed = {c["role"][5:] for c in snap["compute"].values() if c.get("role")}
    for inst, prof in profiles.items():
        try:
            roles = iam.get_instance_profile(InstanceProfileName=prof)["InstanceProfile"]["Roles"]
        except iam.exceptions.NoSuchEntityException:
            continue
        if roles:
            snap["compute"][inst]["role"] = f"role-{roles[0]['RoleName']}"
            needed.add(roles[0]["RoleName"])
    for r in _paginate(iam, "list_roles", "Roles"):
        if r["RoleName"] not in needed and not r["Path"].startswith("/cloudmedic/"):
            continue
        rid = f"role-{r['RoleName']}"
        pols = []
        for ap in _paginate(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=r["RoleName"]):
            pid = ap["PolicyArn"]
            if pid not in snap["iam"]["policies"]:
                meta = iam.get_policy(PolicyArn=pid)["Policy"]
                ver = iam.get_policy_version(PolicyArn=pid, VersionId=meta["DefaultVersionId"])["PolicyVersion"]
                snap["iam"]["policies"][pid] = {"name": ap["PolicyName"], "kind": "managed", **_doc(ver["Document"])}
            pols.append(pid)
        for pname in _paginate(iam, "list_role_policies", "PolicyNames", RoleName=r["RoleName"]):
            doc = iam.get_role_policy(RoleName=r["RoleName"], PolicyName=pname)["PolicyDocument"]
            pid = f"inline:{r['RoleName']}:{pname}"
            snap["iam"]["policies"][pid] = {"name": pname, "kind": "inline", **_doc(doc)}
            pols.append(pid)
        full = iam.get_role(RoleName=r["RoleName"])["Role"]
        boundary = (full.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        if boundary and boundary not in snap["iam"]["policies"]:
            meta = iam.get_policy(PolicyArn=boundary)["Policy"]
            ver = iam.get_policy_version(PolicyArn=boundary, VersionId=meta["DefaultVersionId"])["PolicyVersion"]
            snap["iam"]["policies"][boundary] = {"name": meta["PolicyName"], "kind": "boundary", **_doc(ver["Document"])}
        snap["iam"]["roles"][rid] = {"name": r["RoleName"], "account": acct, "arn": r["Arn"], "policies": pols,
                                     "boundary": boundary, "default_context": {"aws:RequestedRegion": snap["region"]}}
    s3 = session.client("s3")
    for b in s3.list_buckets().get("Buckets", []):
        arn = f"arn:aws:s3:::{b['Name']}"
        rec = {"type": "s3_bucket", "name": b["Name"], "account": acct, "policy": None, "kms_key": None}
        try:
            rec["policy"] = json.loads(s3.get_bucket_policy(Bucket=b["Name"])["Policy"])
        except Exception:
            pass
        try:
            enc = s3.get_bucket_encryption(Bucket=b["Name"])["ServerSideEncryptionConfiguration"]["Rules"][0]
            key = enc["ApplyServerSideEncryptionByDefault"].get("KMSMasterKeyID")
            if key and key.startswith("arn:aws:kms"):
                rec["kms_key"] = key
        except Exception:
            pass
        snap["resources"][arn] = rec
    kms = session.client("kms")
    for k in _paginate(kms, "list_keys", "Keys"):
        try:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            pol = json.loads(kms.get_key_policy(KeyId=k["KeyId"], PolicyName="default")["Policy"])
            snap["resources"][meta["Arn"]] = {"type": "kms_key", "name": k["KeyId"], "account": acct, "policy": pol}
        except Exception:
            continue


def main():
    import boto3
    ap = argparse.ArgumentParser(description="Import a read-only snapshot of an AWS account")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--out", default="snapshot.json")
    ap.add_argument("--no-iam", action="store_true")
    a = ap.parse_args()
    session = boto3.Session(profile_name=a.profile, region_name=a.region)
    snap = import_account(session, include_iam=not a.no_iam)
    with open(a.out, "w") as fh:
        json.dump(snap, fh, indent=1)
    print(f"wrote {a.out}: {len(snap['vpcs'])} VPCs, {len(snap['subnets'])} subnets, {len(snap['compute'])} compute, "
          f"{len(snap['iam']['roles'])} roles, {len(snap['resources'])} resources")


if __name__ == "__main__":
    main()
