"""Live validation of the network model on real AWS infrastructure.

Creates an isolated VPC (10.77.0.0/16, tagged cloudmedic-live=true) with two public subnets and
three t3.micro instances (client in subnet A; server and client2 in subnet B), then injects one
fault at a time, probes real TCP connections from the clients through SSM Run Command, and
compares what happened with what the CloudMedic model predicts for the mirrored snapshot.

Experiments cover the semantics that are easiest to get wrong: stateful SGs vs stateless
NACLs, NACL rule ordering, return traffic on ephemeral ports (including *partial* coverage,
where the model predicts an intermittent failure and a success fraction), SG-to-SG references,
connection refused vs timeout, and same-subnet traffic bypassing NACLs.

Cost: three t3.micro instances and their public IPv4 addresses for roughly 30 to 45 minutes
(free-tier eligible; otherwise a few US cents). Everything is deleted in a finally block, and
`--cleanup` removes anything left behind by an interrupted run.

    python -m cloudmedic.aws.live_network --profile cloudmedic --region us-east-1
    python -m cloudmedic.aws.live_network --profile cloudmedic --region us-east-1 --cleanup
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from ..network import evaluate_flow, nacl_range

TAG = {"Key": "cloudmedic-live", "Value": "true"}
CIDR, SUB_A, SUB_B = "10.77.0.0/16", "10.77.1.0/24", "10.77.2.0/24"
PORT, CLOSED = 8080, 9090
LINUX_EPHEMERAL = (32768, 60999)
PROBES = 24

USER_DATA = f"""#!/bin/bash
mkdir -p /srv && cd /srv && echo ok > index.html
nohup python3 -m http.server {PORT} --bind 0.0.0.0 >/var/log/http.log 2>&1 &
"""


def allow_all():
    return [{"rule": 100, "proto": "-1", "from": 0, "to": 65535, "cidr": "0.0.0.0/0", "action": "allow"}]


def base_model(ips):
    """Snapshot that mirrors the live environment (IDs are symbolic)."""
    return {
        "account_id": "000000000000", "region": "live",
        "vpcs": {"vpc": {"name": "live", "cidr": CIDR, "enable_dns_support": True}},
        "subnets": {"a": {"vpc": "vpc", "cidr": SUB_A, "route_table": "rt", "nacl": "acl-a"},
                    "b": {"vpc": "vpc", "cidr": SUB_B, "route_table": "rt", "nacl": "acl-b"}},
        "route_tables": {"rt": {"vpc": "vpc", "routes": [{"dest": CIDR, "target": "local"}, {"dest": "0.0.0.0/0", "target": "igw-x"}]}},
        "internet_gateways": {"igw-x": {"vpc": "vpc"}}, "nat_gateways": {}, "vpc_peerings": {}, "vpc_endpoints": {},
        "security_groups": {
            "sg-client": {"vpc": "vpc", "ingress": [], "egress": [{"proto": "-1", "from": 0, "to": 65535, "cidr": "0.0.0.0/0"}]},
            "sg-client2": {"vpc": "vpc", "ingress": [], "egress": [{"proto": "-1", "from": 0, "to": 65535, "cidr": "0.0.0.0/0"}]},
            "sg-server": {"vpc": "vpc", "ingress": [{"proto": "tcp", "from": PORT, "to": PORT, "cidr": CIDR}],
                          "egress": [{"proto": "-1", "from": 0, "to": 65535, "cidr": "0.0.0.0/0"}]}},
        "nacls": {"acl-a": {"vpc": "vpc", "ingress": allow_all(), "egress": allow_all()},
                  "acl-b": {"vpc": "vpc", "ingress": allow_all(), "egress": allow_all()}},
        "compute": {
            "client": {"kind": "ec2", "subnet": "a", "private_ip": ips["client"], "security_groups": ["sg-client"], "listening": [],
                       "ephemeral": list(LINUX_EPHEMERAL)},
            "client2": {"kind": "ec2", "subnet": "b", "private_ip": ips["client2"], "security_groups": ["sg-client2"], "listening": [],
                        "ephemeral": list(LINUX_EPHEMERAL)},
            "server": {"kind": "ec2", "subnet": "b", "private_ip": ips["server"], "security_groups": ["sg-server"],
                       "listening": [{"proto": "tcp", "port": PORT}], "ephemeral": list(LINUX_EPHEMERAL)}},
        "external_hosts": {}, "private_zones": {}, "iam": {"roles": {}, "policies": {}}, "resources": {},
    }


def experiments():
    """(name, mutate(model) -> None, probes [(client, port)])"""
    def sg_server(m, rules):
        m["security_groups"]["sg-server"]["ingress"] = rules

    def nacl(m, acl, direction, extra):
        m["nacls"][acl][direction] = extra + allow_all()

    return [
        ("baseline", lambda m: None, [("client", PORT), ("client2", PORT)]),
        ("sg_ingress_removed", lambda m: sg_server(m, []), [("client", PORT)]),
        ("sg_ingress_wrong_port", lambda m: sg_server(m, [{"proto": "tcp", "from": PORT + 1, "to": PORT + 1, "cidr": CIDR}]), [("client", PORT)]),
        ("sg_reference_only_client", lambda m: sg_server(m, [{"proto": "tcp", "from": PORT, "to": PORT, "sg": "sg-client"}]),
         [("client", PORT), ("client2", PORT)]),
        ("nacl_inbound_deny_request", lambda m: nacl(m, "acl-b", "ingress",
                                                     [{"rule": 40, "proto": "tcp", "from": PORT, "to": PORT, "cidr": SUB_A, "action": "deny"}]),
         [("client", PORT)]),
        ("nacl_rule_order_allow_first", lambda m: nacl(m, "acl-b", "ingress", [
            {"rule": 30, "proto": "tcp", "from": PORT, "to": PORT, "cidr": SUB_A, "action": "allow"},
            {"rule": 40, "proto": "tcp", "from": PORT, "to": PORT, "cidr": SUB_A, "action": "deny"}]), [("client", PORT)]),
        ("nacl_return_blocked_stateless", lambda m: nacl(m, "acl-b", "egress",
                                                         [{"rule": 40, "proto": "tcp", "from": 1024, "to": 65535, "cidr": SUB_A, "action": "deny"}]),
         [("client", PORT)]),
        ("nacl_return_partial_ephemeral", lambda m: nacl(m, "acl-a", "ingress", [
            {"rule": 30, "proto": "tcp", "from": 49152, "to": 65535, "cidr": SUB_B, "action": "allow"},
            {"rule": 40, "proto": "tcp", "from": 1024, "to": 65535, "cidr": SUB_B, "action": "deny"}]), [("client", PORT)]),
        ("same_subnet_bypasses_nacl", lambda m: nacl(m, "acl-b", "ingress",
                                                     [{"rule": 40, "proto": "tcp", "from": PORT, "to": PORT, "cidr": CIDR, "action": "deny"}]),
         [("client", PORT), ("client2", PORT)]),
        ("service_not_listening", lambda m: m["security_groups"]["sg-server"]["ingress"].append(
            {"proto": "tcp", "from": CLOSED, "to": CLOSED, "cidr": CIDR}), [("client", CLOSED)]),
    ]


def predict(model, client, port):
    r = evaluate_flow(model, client, "server", "tcp", port)
    frac = 1.0 if r.ok else 0.0
    partial = [c for c in r.failing if c.status == "partial"]
    if partial and len(r.failing) == len(partial):
        frac = 1.0
        for c in partial:
            frac *= c.ctx.get("coverage", 0)
    return {"ok": r.ok, "symptom": r.symptom, "predicted_success_fraction": frac}


# ------------------------------------------------------------------ AWS plumbing

class Live:
    def __init__(self, session):
        self.s = session
        self.ec2 = session.client("ec2")
        self.ssm = session.client("ssm")
        self.iam = session.client("iam")
        self.ids = {}

    def tag(self, rid, name):
        self.ec2.create_tags(Resources=[rid], Tags=[TAG, {"Key": "Name", "Value": f"cloudmedic-live-{name}"}])

    def setup(self):
        e = self.ec2
        vpc = e.create_vpc(CidrBlock=CIDR)["Vpc"]["VpcId"]; self.ids["vpc"] = vpc; self.tag(vpc, "vpc")
        e.get_waiter("vpc_available").wait(VpcIds=[vpc])
        igw = e.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]; self.ids["igw"] = igw; self.tag(igw, "igw")
        e.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
        az = e.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
        rt = e.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]; self.ids["rt"] = rt; self.tag(rt, "rt")
        e.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
        for key, cidr in (("a", SUB_A), ("b", SUB_B)):
            sid = e.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=az)["Subnet"]["SubnetId"]
            self.ids[f"subnet-{key}"] = sid; self.tag(sid, f"subnet-{key}")
            e.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
            e.associate_route_table(RouteTableId=rt, SubnetId=sid)
            acl = e.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]; self.ids[f"acl-{key}"] = acl; self.tag(acl, f"acl-{key}")
            assoc = next(a["NetworkAclAssociationId"] for n in e.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkAcls"]
                         for a in n["Associations"] if a["SubnetId"] == sid)
            e.replace_network_acl_association(AssociationId=assoc, NetworkAclId=acl)
        for key in ("sg-client", "sg-client2", "sg-server"):
            g = e.create_security_group(GroupName=f"cloudmedic-live-{key}", Description="cloudmedic live validation", VpcId=vpc)["GroupId"]
            self.ids[key] = g; self.tag(g, key)
        role = "cloudmedic-live-ssm"
        try:
            self.iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
                Tags=[TAG])
            self.iam.attach_role_policy(RoleName=role, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
            self.iam.create_instance_profile(InstanceProfileName=role, Tags=[TAG])
            self.iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
            time.sleep(12)  # instance profile propagation
        except self.iam.exceptions.EntityAlreadyExistsException:
            pass
        ami = self.s.client("ssm").get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
        layout = {"client": ("subnet-a", "sg-client", ""), "client2": ("subnet-b", "sg-client2", ""), "server": ("subnet-b", "sg-server", USER_DATA)}
        for name, (sub, sg, ud) in layout.items():
            for attempt in range(5):
                try:
                    inst = e.run_instances(ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=self.ids[sub],
                                           SecurityGroupIds=[self.ids[sg]], IamInstanceProfile={"Name": role}, UserData=ud,
                                           MetadataOptions={"HttpTokens": "required"},
                                           TagSpecifications=[{"ResourceType": "instance", "Tags": [TAG, {"Key": "Name", "Value": f"cloudmedic-live-{name}"}]}])
                    break
                except e.exceptions.ClientError as err:
                    if "Invalid IAM Instance Profile" not in str(err) or attempt == 4:
                        raise
                    time.sleep(10)
            self.ids[name] = inst["Instances"][0]["InstanceId"]
        insts = [self.ids[k] for k in layout]
        e.get_waiter("instance_running").wait(InstanceIds=insts)
        desc = e.describe_instances(InstanceIds=insts)["Reservations"]
        ips = {}
        for r in desc:
            for i in r["Instances"]:
                name = next(t["Value"] for t in i["Tags"] if t["Key"] == "Name").replace("cloudmedic-live-", "")
                ips[name] = i["PrivateIpAddress"]
        deadline = time.time() + 600
        while time.time() < deadline:
            online = {i["InstanceId"] for i in self.ssm.describe_instance_information()["InstanceInformationList"] if i["PingStatus"] == "Online"}
            if set(insts) <= online:
                break
            time.sleep(10)
        else:
            raise RuntimeError("instances did not register with SSM within 10 minutes")
        return ips

    def apply_model(self, model):
        """Push the model's SG and NACL configuration to the live VPC."""
        e = self.ec2
        for key in ("sg-client", "sg-client2", "sg-server"):
            gid = self.ids[key]
            g = e.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
            if g["IpPermissions"]:
                e.revoke_security_group_ingress(GroupId=gid, IpPermissions=g["IpPermissions"])
            perms = []
            for r in model["security_groups"][key]["ingress"]:
                p = {"IpProtocol": r["proto"], "FromPort": r["from"], "ToPort": r["to"]}
                if "cidr" in r:
                    p["IpRanges"] = [{"CidrIp": r["cidr"]}]
                else:
                    p["UserIdGroupPairs"] = [{"GroupId": self.ids[r["sg"]]}]
                perms.append(p)
            if perms:
                e.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
        for key in ("acl-a", "acl-b"):
            aid = self.ids[key]
            cur = e.describe_network_acls(NetworkAclIds=[aid])["NetworkAcls"][0]["Entries"]
            for ent in cur:
                if ent["RuleNumber"] < 32767:
                    e.delete_network_acl_entry(NetworkAclId=aid, RuleNumber=ent["RuleNumber"], Egress=ent["Egress"])
            for direction in ("ingress", "egress"):
                for r in model["nacls"][key][direction]:
                    kw = {"NetworkAclId": aid, "RuleNumber": r["rule"], "Protocol": "6" if r["proto"] == "tcp" else "-1",
                          "RuleAction": r["action"], "Egress": direction == "egress", "CidrBlock": r["cidr"]}
                    if r["proto"] == "tcp":
                        kw["PortRange"] = {"From": r["from"], "To": r["to"]}
                    e.create_network_acl_entry(**kw)
        time.sleep(15)  # let SG/NACL changes propagate

    def probe(self, client, ip, port, n=PROBES):
        script = (f"ok=0; ref=0; to=0; for i in $(seq 1 {n}); do out=$(timeout 4 bash -c '</dev/tcp/{ip}/{port}' 2>&1); rc=$?; "
                  f"if [ $rc -eq 0 ]; then ok=$((ok+1)); elif echo \"$out\" | grep -qi refused; then ref=$((ref+1)); else to=$((to+1)); fi; "
                  f"done; echo $ok $ref $to")
        cid = self.ssm.send_command(InstanceIds=[self.ids[client]], DocumentName="AWS-RunShellScript",
                                    Parameters={"commands": [script]}, TimeoutSeconds=300)["Command"]["CommandId"]
        for _ in range(90):
            time.sleep(3)
            try:
                inv = self.ssm.get_command_invocation(CommandId=cid, InstanceId=self.ids[client])
            except self.ssm.exceptions.InvocationDoesNotExist:
                continue
            if inv["Status"] in ("Success", "Failed", "TimedOut", "Cancelled"):
                ok, ref, to = map(int, inv["StandardOutputContent"].split()[:3])
                return {"success": ok, "refused": ref, "timeout": to, "n": n}
        raise RuntimeError("SSM command did not finish")

    def teardown(self):
        cleanup(self.s)


def cleanup(session):
    ec2, iam = session.client("ec2"), session.client("iam")
    flt = [{"Name": "tag:cloudmedic-live", "Values": ["true"]}]
    insts = [i["InstanceId"] for r in ec2.describe_instances(Filters=flt + [{"Name": "instance-state-name", "Values": ["pending", "running", "stopped", "stopping"]}])["Reservations"] for i in r["Instances"]]
    if insts:
        ec2.terminate_instances(InstanceIds=insts)
        ec2.get_waiter("instance_terminated").wait(InstanceIds=insts)
    for v in ec2.describe_vpcs(Filters=flt)["Vpcs"]:
        vid = v["VpcId"]
        for g in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vid]}])["SecurityGroups"]:
            if g["GroupName"] != "default" and g["IpPermissions"]:
                ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
        for g in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vid]}])["SecurityGroups"]:
            if g["GroupName"] != "default":
                ec2.delete_security_group(GroupId=g["GroupId"])
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vid]}])["Subnets"]:
            ec2.delete_subnet(SubnetId=s["SubnetId"])
        for n in ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vid]}])["NetworkAcls"]:
            if not n["IsDefault"]:
                ec2.delete_network_acl(NetworkAclId=n["NetworkAclId"])
        for rt in ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vid]}])["RouteTables"]:
            if not any(a.get("Main") for a in rt["Associations"]):
                for a in rt["Associations"]:
                    ec2.disassociate_route_table(AssociationId=a["RouteTableAssociationId"])
                ec2.delete_route_table(RouteTableId=rt["RouteTableId"])
        for g in ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vid]}])["InternetGateways"]:
            ec2.detach_internet_gateway(InternetGatewayId=g["InternetGatewayId"], VpcId=vid)
            ec2.delete_internet_gateway(InternetGatewayId=g["InternetGatewayId"])
        ec2.delete_vpc(VpcId=vid)
    role = "cloudmedic-live-ssm"
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=role, RoleName=role)
    except Exception:
        pass
    for fn in (lambda: iam.delete_instance_profile(InstanceProfileName=role),
               lambda: iam.detach_role_policy(RoleName=role, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
               lambda: iam.delete_role(RoleName=role)):
        try:
            fn()
        except Exception:
            pass
    print("cleanup complete")


def main():
    import boto3
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=None)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--out", default="results/live_network.json")
    a = ap.parse_args()
    session = boto3.Session(profile_name=a.profile, region_name=a.region)
    if a.cleanup:
        cleanup(session)
        return
    live = Live(session)
    rows = []
    try:
        ips = live.setup()
        for name, mutate, probes in experiments():
            model = base_model(ips)
            mutate(model)
            live.apply_model(model)
            for client, port in probes:
                pred = predict(model, client, port)
                obs = live.probe(client, ips["server"], port)
                frac = obs["success"] / obs["n"]
                observed = "ok" if frac == 1 else ("fail" if frac == 0 else "partial")
                expected = "ok" if pred["ok"] else ("partial" if 0 < pred["predicted_success_fraction"] < 1 else "fail")
                sym_ok = True
                if observed == "fail":
                    sym_ok = (pred["symptom"] == "connection_refused") == (obs["refused"] > obs["timeout"])
                row = {"experiment": name, "client": client, "port": port, "prediction": pred, "observation": obs,
                       "observed": observed, "expected": expected, "agree": observed == expected and sym_ok}
                rows.append(row)
                print(json.dumps(row), flush=True)
    finally:
        live.teardown()
    out = {"n": len(rows), "agreement": sum(r["agree"] for r in rows) / max(1, len(rows)), "rows": rows}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({"n": out["n"], "agreement": out["agreement"]}))


if __name__ == "__main__":
    main()
