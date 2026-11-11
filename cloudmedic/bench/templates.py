"""Healthy reference architectures.

Each template builds a randomised but working AWS environment (resource IDs, CIDRs, ports,
names, account numbers and NACL style vary with the seed) together with the list of intents
that must succeed in it. Faults are injected into these later by the mutation operators.
"""
from __future__ import annotations

import ipaddress
import random


class Builder:
    def __init__(self, rng: random.Random, account: str | None = None, region: str = "us-east-1"):
        self.rng = rng
        self.snap = {
            "account_id": account or str(rng.randint(10**11, 10**12 - 1)),
            "region": region,
            "vpcs": {}, "subnets": {}, "route_tables": {}, "internet_gateways": {}, "nat_gateways": {},
            "vpc_peerings": {}, "vpc_endpoints": {}, "security_groups": {}, "nacls": {}, "compute": {},
            "external_hosts": {}, "private_zones": {},
            "iam": {"roles": {}, "policies": {}},
            "organizations": {"scps": {}, "accounts": {}},
            "resources": {},
        }
        self.intents: list[dict] = []

    def rid(self, prefix: str, short: bool = False) -> str:
        return f"{prefix}-{self.rng.getrandbits(32 if short else 68):0{8 if short else 17}x}"

    # ---- network
    def vpc(self, name, cidr):
        v = self.rid("vpc")
        self.snap["vpcs"][v] = {"name": name, "cidr": cidr, "enable_dns_support": True, "enable_dns_hostnames": True}
        return v

    def route_table(self, name, vpc, routes=()):
        r = self.rid("rtb")
        self.snap["route_tables"][r] = {"name": name, "vpc": vpc,
                                        "routes": [{"dest": self.snap["vpcs"][vpc]["cidr"], "target": "local"}, *routes]}
        return r

    def nacl(self, name, vpc, ingress=None, egress=None):
        n = self.rid("acl")
        allow_all = [{"rule": 100, "proto": "-1", "from": 0, "to": 65535, "cidr": "0.0.0.0/0", "action": "allow"}]
        self.snap["nacls"][n] = {"name": name, "vpc": vpc,
                                 "ingress": ingress if ingress is not None else [dict(r) for r in allow_all],
                                 "egress": egress if egress is not None else [dict(r) for r in allow_all]}
        return n

    def subnet(self, name, vpc, cidr, rt, nacl):
        s = self.rid("subnet")
        self.snap["subnets"][s] = {"name": name, "vpc": vpc, "cidr": cidr, "route_table": rt, "nacl": nacl}
        return s

    def igw(self, name, vpc):
        g = self.rid("igw")
        self.snap["internet_gateways"][g] = {"name": name, "vpc": vpc}
        return g

    def nat(self, name, subnet):
        n = self.rid("nat")
        self.snap["nat_gateways"][n] = {"name": name, "subnet": subnet, "public_ip": self.public_ip()}
        return n

    def sg(self, name, vpc, ingress=(), egress=None):
        g = self.rid("sg")
        self.snap["security_groups"][g] = {
            "name": name, "vpc": vpc, "ingress": list(ingress),
            "egress": list(egress) if egress is not None else [{"proto": "-1", "from": 0, "to": 65535, "cidr": "0.0.0.0/0"}]}
        return g

    def public_ip(self):
        return f"{self.rng.choice([3, 18, 34, 44, 52, 54])}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"

    def host_ip(self, subnet, offset=None):
        net = ipaddress.ip_network(self.snap["subnets"][subnet]["cidr"])
        used = {c.get("private_ip") for c in self.snap["compute"].values()}
        while True:
            ip = str(net.network_address + (offset or self.rng.randint(10, 250)))
            if ip not in used:
                return ip
            offset = None

    def compute(self, name, kind, subnet, sgs, role=None, listening=(), public=False, ephemeral=None, prefix=None):
        cid = self.rid(prefix or {"ec2": "i", "lambda": "fn", "rds": "db"}[kind], short=kind != "ec2")
        if kind == "lambda":
            cid = f"fn-{name}"
        if kind == "rds":
            cid = f"db-{name}"
        self.snap["compute"][cid] = {
            "name": name, "kind": kind, "subnet": subnet,
            "private_ip": self.host_ip(subnet) if subnet else None,
            "public_ip": self.public_ip() if public else None,
            "security_groups": list(sgs), "role": role,
            "listening": [{"proto": "tcp", "port": p} for p in listening],
            "ephemeral": list(ephemeral or ((1024, 65535) if kind == "lambda" else (32768, 60999))),
        }
        return cid

    def external(self, key, name, ip, hostname=None, listening=(), trusted=False):
        self.snap["external_hosts"][key] = {"name": name, "ip": ip, "hostname": hostname, "trusted": trusted,
                                            "listening": [{"proto": "tcp", "port": p} for p in listening]}
        return key

    def zone(self, name, vpcs, records):
        z = "Z" + "".join(self.rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(13))
        self.snap["private_zones"][z] = {"name": name, "vpcs": list(vpcs), "records": dict(records)}
        return z

    # ---- IAM
    def policy(self, pid, name, statements, kind="managed"):
        for i, st in enumerate(statements):
            st.setdefault("Sid", f"S{i + 1}")
        self.snap["iam"]["policies"][pid] = {"name": name, "kind": kind, "Version": "2012-10-17", "Statement": statements}
        return pid

    def role(self, rid, name, policies, boundary=None, account=None, default_context=None):
        self.snap["iam"]["roles"][rid] = {"name": name, "account": account or self.snap["account_id"],
                                          "policies": list(policies), "boundary": boundary,
                                          "default_context": dict(default_context or {})}
        return rid

    def arn_role(self, rid):
        r = self.snap["iam"]["roles"][rid]
        return f"arn:aws:iam::{r['account']}:role/{r['name']}"

    def scp_baseline(self, allowed_regions):
        org = self.snap["organizations"]
        org["scps"]["p-FullAWSAccess"] = {"name": "FullAWSAccess", "Statement": [
            {"Sid": "FullAccess", "Effect": "Allow", "Action": "*", "Resource": "*"}]}
        org["scps"]["p-guardrails"] = {"name": "SecurityGuardrails", "Statement": [
            {"Sid": "AllowAll", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "DenyTrailTampering", "Effect": "Deny", "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"], "Resource": "*"},
            {"Sid": "DenyLeaveOrg", "Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"},
            {"Sid": "RegionLock", "Effect": "Deny", "NotAction": ["iam:*", "sts:*", "organizations:*"], "Resource": "*",
             "Condition": {"StringNotEquals": {"aws:RequestedRegion": allowed_regions}}},
        ]}
        org["accounts"][self.snap["account_id"]] = ["p-FullAWSAccess", "p-guardrails"]

    def bucket(self, name, policy_statements=None, kms_key=None, account=None):
        arn = f"arn:aws:s3:::{name}"
        self.snap["resources"][arn] = {"type": "s3_bucket", "name": name, "account": account or self.snap["account_id"],
                                       "policy": {"Version": "2012-10-17", "Statement": policy_statements} if policy_statements else None,
                                       "kms_key": kms_key}
        return arn

    def kms_key(self, alias, policy_statements, account=None):
        acct = account or self.snap["account_id"]
        kid = f"{self.rng.getrandbits(32):08x}-{self.rng.getrandbits(16):04x}-4{self.rng.getrandbits(12):03x}-a{self.rng.getrandbits(12):03x}-{self.rng.getrandbits(48):012x}"
        arn = f"arn:aws:kms:{self.snap['region']}:{acct}:key/{kid}"
        self.snap["resources"][arn] = {"type": "kms_key", "name": alias, "account": acct,
                                       "policy": {"Version": "2012-10-17", "Statement": policy_statements}}
        return arn

    def generic_resource(self, arn, rtype, name, policy_statements=None):
        self.snap["resources"][arn] = {"type": rtype, "name": name, "account": self.snap["account_id"],
                                       "policy": {"Version": "2012-10-17", "Statement": policy_statements} if policy_statements else None}
        return arn

    def intent(self, desc, **kw):
        self.intents.append({**kw, "desc": desc})


def _tight_nacl_rules(rng, ingress_specs, egress_specs):
    """NACL rule lists from (proto, lo, hi, cidr) tuples, numbered like a human would."""
    step = rng.choice([10, 100])
    start = rng.choice([100, 100, 10])

    def build(specs):
        return [{"rule": start + i * step, "proto": p, "from": lo, "to": hi, "cidr": c, "action": "allow"}
                for i, (p, lo, hi, c) in enumerate(specs)]
    return build(ingress_specs), build(egress_specs)


def _octet(rng, used=set()):
    while True:
        o = rng.randint(1, 250)
        if o not in used:
            used.add(o)
            return o


EXTERNALS = [
    ("payments-api", "Payments partner API", "api.payments-partner.example", 443),
    ("geo-api", "Geocoding SaaS", "api.geocode-service.example", 443),
    ("pkg-mirror", "Package mirror", "mirror.packages.example", 443),
]


def _common_externals(b: Builder, office_cidr: str):
    b.external("internet-user", "Customer browser", f"198.51.100.{b.rng.randint(10, 60)}")
    b.external("internet-scanner", "Untrusted internet host", "198.51.100.66")
    b.external("office-admin", "Office workstation", office_cidr.split("/")[0], trusted=True)
    key, name, host, port = b.rng.choice(EXTERNALS)
    b.external(key, name, f"192.0.2.{b.rng.randint(10, 250)}", hostname=host, listening=[port])
    return key, host


# ======================================================================= T1
def three_tier_web(rng: random.Random) -> Builder:
    b = Builder(rng)
    a = rng.randint(1, 250)
    tight = rng.random() < 0.6
    app_port = rng.choice([8080, 8000, 3000, 9000])
    db_port, engine = rng.choice([(5432, "postgres"), (3306, "mysql")])
    office = f"203.0.113.{rng.randint(2, 250)}/32"
    vpc = b.vpc("prod-web-vpc", f"10.{a}.0.0/16")
    igw = b.igw("prod-igw", vpc)
    pub_c, app_c, db_c = f"10.{a}.1.0/24", f"10.{a}.11.0/24", f"10.{a}.21.0/24"
    rt_pub = b.route_table("public-rt", vpc, [{"dest": "0.0.0.0/0", "target": igw}])
    if tight:
        ai, ae = _tight_nacl_rules(rng, [("tcp", 443, 443, "0.0.0.0/0"), ("tcp", 80, 80, "0.0.0.0/0"), ("tcp", 22, 22, office),
                                         ("tcp", 1024, 65535, "0.0.0.0/0")],
                                   [("tcp", 443, 443, "0.0.0.0/0"), ("tcp", 80, 80, "0.0.0.0/0"), ("tcp", app_port, app_port, app_c),
                                    ("tcp", 1024, 65535, "0.0.0.0/0")])
        acl_pub = b.nacl("public-nacl", vpc, ai, ae)
        ai, ae = _tight_nacl_rules(rng, [("tcp", app_port, app_port, pub_c), ("tcp", 1024, 65535, "0.0.0.0/0")],
                                   [("tcp", db_port, db_port, db_c), ("tcp", 443, 443, "0.0.0.0/0"), ("tcp", 1024, 65535, pub_c)])
        acl_app = b.nacl("app-nacl", vpc, ai, ae)
        ai, ae = _tight_nacl_rules(rng, [("tcp", db_port, db_port, app_c)], [("tcp", 1024, 65535, app_c)])
        acl_db = b.nacl("db-nacl", vpc, ai, ae)
    else:
        acl_pub = acl_app = acl_db = b.nacl("default-nacl", vpc)
    s_pub = b.subnet("public-a", vpc, pub_c, rt_pub, acl_pub)
    nat = b.nat("nat-public-a", s_pub)
    rt_app = b.route_table("app-private-rt", vpc, [{"dest": "0.0.0.0/0", "target": nat}])
    rt_db = b.route_table("db-isolated-rt", vpc)
    s_app = b.subnet("app-private-a", vpc, app_c, rt_app, acl_app)
    s_db = b.subnet("db-private-a", vpc, db_c, rt_db, acl_db)
    sg_web = b.sg("web-sg", vpc, [{"proto": "tcp", "from": 443, "to": 443, "cidr": "0.0.0.0/0"},
                                  {"proto": "tcp", "from": 80, "to": 80, "cidr": "0.0.0.0/0"},
                                  {"proto": "tcp", "from": 22, "to": 22, "cidr": office}])
    sg_app = b.sg("app-sg", vpc, [{"proto": "tcp", "from": app_port, "to": app_port, "sg": sg_web}])
    sg_db = b.sg(f"{engine}-sg", vpc, [{"proto": "tcp", "from": db_port, "to": db_port, "sg": sg_app}])
    cfg = b.bucket(f"acme-app-config-{a}")
    b.policy("pol-app-config", "AppConfigRead", [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"{cfg}/app/*"},
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": cfg}])
    b.policy("pol-web-logs", "WebLogs", [{"Effect": "Allow", "Action": ["logs:PutLogEvents", "logs:CreateLogStream"], "Resource": "*"}])
    b.role("role-app", "app-server-role", ["pol-app-config"], default_context={"aws:RequestedRegion": b.snap["region"]})
    b.role("role-web", "web-server-role", ["pol-web-logs"], default_context={"aws:RequestedRegion": b.snap["region"]})
    b.scp_baseline([b.snap["region"]])
    web = b.compute("web-1", "ec2", s_pub, [sg_web], "role-web", [443, 80, 22], public=True)
    app = b.compute("app-1", "ec2", s_app, [sg_app], "role-app", [app_port, 22])
    db = b.compute(f"{engine}-main", "rds", s_db, [sg_db], None, [db_port])
    ext, host = _common_externals(b, office)
    b.zone("corp.internal", [vpc], {"db.corp.internal": b.snap["compute"][db]["private_ip"],
                                    "app.corp.internal": b.snap["compute"][app]["private_ip"]})
    b.intent("customers open the website over HTTPS", kind="network", src="internet-user", dst=web, proto="tcp", port=443)
    b.intent("admins SSH to the web server from the office", kind="network", src="office-admin", dst=web, proto="tcp", port=22)
    b.intent(f"web tier calls the app tier on port {app_port}", kind="network", src=web, dst=app, proto="tcp", port=app_port)
    b.intent(f"app server connects to the {engine} database by DNS name", kind="network", src=app, dst="db.corp.internal",
             proto="tcp", port=db_port)
    b.intent(f"app server calls the external API {host}", kind="network", src=app, dst=host, proto="tcp", port=443)
    b.intent("app server reads its settings file from S3", kind="iam", principal="role-app", action="s3:GetObject",
             resource=f"{cfg}/app/settings.json", context={})
    return b


# ======================================================================= T2
def serverless_api(rng: random.Random) -> Builder:
    b = Builder(rng)
    a = rng.randint(1, 250)
    db_port, engine = rng.choice([(5432, "aurora-postgres"), (3306, "aurora-mysql")])
    vpc = b.vpc("orders-vpc", f"10.{a}.0.0/16")
    igw = b.igw("orders-igw", vpc)
    acl = b.nacl("default-nacl", vpc)
    rt_pub = b.route_table("public-rt", vpc, [{"dest": "0.0.0.0/0", "target": igw}])
    s_pub = b.subnet("public-a", vpc, f"10.{a}.0.0/24", rt_pub, acl)
    nat = b.nat("nat-a", s_pub)
    rt_priv = b.route_table("private-rt", vpc, [{"dest": "0.0.0.0/0", "target": nat}])
    s_l1 = b.subnet("lambda-private-a", vpc, f"10.{a}.10.0/24", rt_priv, acl)
    b.subnet("lambda-private-b", vpc, f"10.{a}.11.0/24", rt_priv, acl)
    rt_db = b.route_table("db-rt", vpc)
    s_db = b.subnet("db-a", vpc, f"10.{a}.20.0/24", rt_db, acl)
    vpce = b.rid("vpce")
    b.snap["vpc_endpoints"][vpce] = {"name": "s3-gateway", "vpc": vpc, "service": "s3", "route_tables": [rt_priv], "policy": None}
    sg_l = b.sg("orders-lambda-sg", vpc, [])
    sg_db = b.sg("orders-db-sg", vpc, [{"proto": "tcp", "from": db_port, "to": db_port, "sg": sg_l}])
    acct = b.snap["account_id"]
    key = b.kms_key("alias/orders-data", [
        {"Sid": "EnableIAMUserPermissions", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
         "Action": "kms:*", "Resource": "*"}])
    bucket_name = f"orders-data-{acct[-4:]}-{a}"
    bucket = b.bucket(bucket_name, [
        {"Sid": "DenyOutsideVpce", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
         "Condition": {"StringNotEquals": {"aws:SourceVpce": vpce}}}], kms_key=key)
    b.snap["vpc_endpoints"][vpce]["policy"] = {"Version": "2012-10-17", "Statement": [
        {"Sid": "OrdersBucketOnly", "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
         "Resource": [bucket, f"{bucket}/*"]}]}
    loggrp = f"arn:aws:logs:{b.snap['region']}:{acct}:log-group:/aws/lambda/orders-api:*"
    b.policy("pol-orders-lambda", "OrdersLambdaAccess", [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": f"{bucket}/*"},
        {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": key},
        {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": loggrp}])
    b.role("role-orders", "orders-api-lambda-role", ["pol-orders-lambda"],
           default_context={"aws:SourceVpce": vpce, "aws:RequestedRegion": b.snap["region"]})
    b.scp_baseline([b.snap["region"], "eu-west-1"])
    fn = b.compute("orders-api", "lambda", s_l1, [sg_l], "role-orders", [])
    db = b.compute("orders-cluster", "rds", s_db, [sg_db], None, [db_port])
    ext, host = _common_externals(b, f"203.0.113.{rng.randint(2, 250)}/32")
    b.zone("orders.internal", [vpc], {"db.orders.internal": b.snap["compute"][db]["private_ip"]})
    b.intent(f"orders Lambda calls {host}", kind="network", src=fn, dst=host, proto="tcp", port=443)
    b.intent("orders Lambda connects to its Aurora cluster", kind="network", src=fn, dst="db.orders.internal", proto="tcp", port=db_port)
    b.intent("orders Lambda reads an order file from S3 (SSE-KMS)", kind="iam", principal="role-orders", action="s3:GetObject",
             resource=f"{bucket}/orders/2026/11/order-{rng.randint(1000, 9999)}.json", context={})
    b.intent("orders Lambda writes a receipt to S3 (SSE-KMS)", kind="iam", principal="role-orders", action="s3:PutObject",
             resource=f"{bucket}/receipts/r-{rng.randint(1000, 9999)}.pdf", context={})
    b.intent("orders Lambda writes CloudWatch logs", kind="iam", principal="role-orders", action="logs:PutLogEvents",
             resource=loggrp.replace(":*", ":log-stream:2026/11/11/[$LATEST]abc"), context={})
    return b


# ======================================================================= T3
def data_platform(rng: random.Random) -> Builder:
    b = Builder(rng)
    acct = b.snap["account_id"]
    partner_acct = str(rng.randint(10**11, 10**12 - 1))
    corp_cidr = f"203.0.113.0/{rng.choice([24, 25, 26])}"
    b.scp_baseline([b.snap["region"]])
    b.snap["organizations"]["accounts"][partner_acct] = ["p-FullAWSAccess"]
    lake_name = f"analytics-lake-{acct[-6:]}"
    lake = f"arn:aws:s3:::{lake_name}"
    partner_name = rng.choice(["partner-analytics", "vendor-insights", "bi-contractor"])
    b.role("role-partner", f"{partner_name}-reader", [], account=partner_acct,
           default_context={"aws:RequestedRegion": b.snap["region"]})
    partner_arn = b.arn_role("role-partner")
    key = b.kms_key("alias/analytics-lake", [
        {"Sid": "EnableIAMUserPermissions", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
         "Action": "kms:*", "Resource": "*"},
        {"Sid": "AllowPartnerDecrypt", "Effect": "Allow", "Principal": {"AWS": partner_arn},
         "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*"}])
    b.bucket(lake_name, [
        {"Sid": "PartnerSharedRead", "Effect": "Allow", "Principal": {"AWS": partner_arn}, "Action": "s3:GetObject",
         "Resource": f"{lake}/shared/*"},
        {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": [lake, f"{lake}/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}], kms_key=key)
    b.policy("pol-dev-boundary", "DeveloperBoundary", [
        {"Effect": "Allow", "Action": ["s3:*", "kms:Decrypt", "kms:GenerateDataKey", "athena:*", "glue:Get*", "logs:*"], "Resource": "*"},
        {"Effect": "Deny", "Action": ["iam:*", "organizations:*"], "Resource": "*"}], kind="boundary")
    b.policy("pol-analyst", "AnalystLakeRead", [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"{lake}/curated/*",
         "Condition": {"IpAddress": {"aws:SourceIp": corp_cidr}}},
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": lake},
        {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": key}])
    b.policy("pol-etl", "EtlLakeWrite", [
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": [f"{lake}/raw/*", f"{lake}/curated/*"]},
        {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": key}])
    b.policy("pol-partner", "PartnerLakeRead", [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{lake}/shared/*"},
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key}])
    b.snap["iam"]["roles"]["role-partner"]["policies"] = ["pol-partner"]
    office_ip = str(list(__import__("ipaddress").ip_network(corp_cidr).hosts())[rng.randint(1, 20)])
    b.role("role-analyst", "data-analyst", ["pol-analyst"], boundary="pol-dev-boundary",
           default_context={"aws:SourceIp": office_ip, "aws:SecureTransport": "true", "aws:RequestedRegion": b.snap["region"]})
    b.role("role-etl", "nightly-etl", ["pol-etl"], boundary="pol-dev-boundary",
           default_context={"aws:SecureTransport": "true", "aws:RequestedRegion": b.snap["region"]})
    b.snap["iam"]["roles"]["role-partner"]["default_context"]["aws:SecureTransport"] = "true"
    day = rng.randint(1, 28)
    b.intent("analyst reads a curated table file from the office", kind="iam", principal="role-analyst", action="s3:GetObject",
             resource=f"{lake}/curated/sales/2026-11-{day:02d}.parquet", context={})
    b.intent("analyst lists the lake bucket", kind="iam", principal="role-analyst", action="s3:ListBucket", resource=lake, context={})
    b.intent("nightly ETL writes raw files", kind="iam", principal="role-etl", action="s3:PutObject",
             resource=f"{lake}/raw/events/dt=2026-11-{day:02d}/part-0001.json", context={})
    b.intent("partner account reads the shared export", kind="iam", principal="role-partner", action="s3:GetObject",
             resource=f"{lake}/shared/exports/weekly-{day:02d}.csv", context={})
    return b


# ======================================================================= T4
def peered_shared_services(rng: random.Random) -> Builder:
    b = Builder(rng)
    a, c = rng.sample(range(1, 250), 2)
    office = f"203.0.113.{rng.randint(2, 250)}/32"
    cache_port = 6379
    search_port = rng.choice([9200, 443])
    v_app = b.vpc("app-vpc", f"10.{a}.0.0/16")
    v_sh = b.vpc("shared-services-vpc", f"10.{c}.0.0/16")
    pcx = b.rid("pcx")
    b.snap["vpc_peerings"][pcx] = {"name": "app-to-shared", "requester_vpc": v_app, "accepter_vpc": v_sh, "status": "active"}
    igw = b.igw("app-igw", v_app)
    tight = rng.random() < 0.5
    pub_c, priv_c = f"10.{a}.0.0/24", f"10.{a}.10.0/24"
    sh_c = f"10.{c}.20.0/24"
    acl_app = b.nacl("app-default-nacl", v_app)
    if tight:
        ai, ae = _tight_nacl_rules(rng, [("tcp", cache_port, cache_port, f"10.{a}.0.0/16"),
                                         ("tcp", search_port, search_port, f"10.{a}.0.0/16"),
                                         ("tcp", 1024, 65535, "0.0.0.0/0")],
                                   [("tcp", 1024, 65535, f"10.{a}.0.0/16"), ("tcp", 443, 443, "0.0.0.0/0")])
        acl_sh = b.nacl("shared-nacl", v_sh, ai, ae)
    else:
        acl_sh = b.nacl("shared-default-nacl", v_sh)
    rt_pub = b.route_table("app-public-rt", v_app, [{"dest": "0.0.0.0/0", "target": igw}, {"dest": f"10.{c}.0.0/16", "target": pcx}])
    s_pub = b.subnet("app-public-a", v_app, pub_c, rt_pub, acl_app)
    nat = b.nat("app-nat", s_pub)
    rt_priv = b.route_table("app-private-rt", v_app, [{"dest": "0.0.0.0/0", "target": nat}, {"dest": f"10.{c}.0.0/16", "target": pcx}])
    s_priv = b.subnet("app-private-a", v_app, priv_c, rt_priv, acl_app)
    rt_sh = b.route_table("shared-rt", v_sh, [{"dest": f"10.{a}.0.0/16", "target": pcx}])
    s_sh = b.subnet("shared-a", v_sh, sh_c, rt_sh, acl_sh)
    sg_bastion = b.sg("bastion-sg", v_app, [{"proto": "tcp", "from": 22, "to": 22, "cidr": office}])
    sg_app = b.sg("app-sg", v_app, [{"proto": "tcp", "from": 22, "to": 22, "sg": sg_bastion}])
    sg_cache = b.sg("redis-sg", v_sh, [{"proto": "tcp", "from": cache_port, "to": cache_port, "cidr": priv_c}])
    sg_search = b.sg("search-sg", v_sh, [{"proto": "tcp", "from": search_port, "to": search_port, "cidr": f"10.{a}.0.0/16"}])
    b.policy("pol-app", "AppRuntime", [{"Effect": "Allow", "Action": ["logs:PutLogEvents", "secretsmanager:GetSecretValue"], "Resource": "*"}])
    b.role("role-app", "app-runtime-role", ["pol-app"], default_context={"aws:RequestedRegion": b.snap["region"]})
    b.scp_baseline([b.snap["region"]])
    bastion = b.compute("bastion", "ec2", s_pub, [sg_bastion], None, [22], public=True)
    app = b.compute("app-worker-1", "ec2", s_priv, [sg_app], "role-app", [22, 8080])
    cache = b.compute("redis-primary", "ec2", s_sh, [sg_cache], None, [cache_port])
    search = b.compute("search-node-1", "ec2", s_sh, [sg_search], None, [search_port])
    ext, host = _common_externals(b, office)
    b.zone("shared.internal", [v_app, v_sh], {"cache.shared.internal": b.snap["compute"][cache]["private_ip"],
                                              "search.shared.internal": b.snap["compute"][search]["private_ip"]})
    b.intent("app worker connects to Redis in the shared-services VPC", kind="network", src=app, dst="cache.shared.internal",
             proto="tcp", port=cache_port)
    b.intent("app worker queries the search cluster in the shared VPC", kind="network", src=app, dst=search, proto="tcp", port=search_port)
    b.intent("admins SSH to the bastion from the office", kind="network", src="office-admin", dst=bastion, proto="tcp", port=22)
    b.intent("bastion SSHes to the private app worker", kind="network", src=bastion, dst=app, proto="tcp", port=22)
    b.intent(f"app worker downloads from {host}", kind="network", src=app, dst=host, proto="tcp", port=443)
    return b


# ======================================================================= T5
def queue_workers(rng: random.Random) -> Builder:
    b = Builder(rng)
    a = rng.randint(1, 250)
    acct = b.snap["account_id"]
    region = b.snap["region"]
    metrics_port = rng.choice([8080, 9090, 8086])
    vpc = b.vpc("workers-vpc", f"10.{a}.0.0/16")
    igw = b.igw("workers-igw", vpc)
    pub_c, wk_c, ops_c = f"10.{a}.0.0/24", f"10.{a}.32.0/20", f"10.{a}.64.0/24"
    ai, ae = _tight_nacl_rules(rng, [("tcp", 1024, 65535, "0.0.0.0/0")],
                               [("tcp", 443, 443, "0.0.0.0/0"), ("tcp", metrics_port, metrics_port, ops_c), ("tcp", 80, 80, "0.0.0.0/0")])
    acl_wk = b.nacl("workers-nacl", vpc, ai, ae)
    acl_pub = b.nacl("public-nacl", vpc)
    ai, ae = _tight_nacl_rules(rng, [("tcp", metrics_port, metrics_port, wk_c), ("tcp", 22, 22, pub_c)], [("tcp", 1024, 65535, f"10.{a}.0.0/16")])
    acl_ops = b.nacl("ops-nacl", vpc, ai, ae)
    rt_pub = b.route_table("public-rt", vpc, [{"dest": "0.0.0.0/0", "target": igw}])
    s_pub = b.subnet("public-a", vpc, pub_c, rt_pub, acl_pub)
    nat = b.nat("workers-nat", s_pub)
    rt_wk = b.route_table("workers-rt", vpc, [{"dest": "0.0.0.0/0", "target": nat}])
    s_wk = b.subnet("workers-a", vpc, wk_c, rt_wk, acl_wk)
    s_ops = b.subnet("ops-a", vpc, ops_c, b.route_table("ops-rt", vpc), acl_ops)
    sg_w = b.sg("worker-sg", vpc, [])
    sg_m = b.sg("metrics-sg", vpc, [{"proto": "tcp", "from": metrics_port, "to": metrics_port, "sg": sg_w}])
    queue = b.generic_resource(f"arn:aws:sqs:{region}:{acct}:jobs-queue", "sqs_queue", "jobs-queue", [
        {"Sid": "OwnerAccount", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"}, "Action": "sqs:*",
         "Resource": f"arn:aws:sqs:{region}:{acct}:jobs-queue"}])
    table = b.generic_resource(f"arn:aws:dynamodb:{region}:{acct}:table/job-results", "dynamodb_table", "job-results")
    secret = b.generic_resource(f"arn:aws:secretsmanager:{region}:{acct}:secret:worker/api-token-{rng.choice('AbCdEf')}{rng.randint(10000, 99999)}",
                                "secret", "worker/api-token")
    b.policy("pol-worker", "WorkerAccess", [
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": queue},
        {"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem"], "Resource": table},
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret}])
    b.policy("pol-producer", "ProducerSend", [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue}])
    b.policy("pol-legacy-admin", "LegacyAdminDoNotUse", [{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    b.role("role-worker", "queue-worker-role", ["pol-worker"], default_context={"aws:RequestedRegion": region})
    b.role("role-producer", "job-producer-role", ["pol-producer"], default_context={"aws:RequestedRegion": region})
    b.scp_baseline([region])
    w = b.compute("worker-1", "ec2", s_wk, [sg_w], "role-worker", [])
    m = b.compute("metrics-1", "ec2", s_ops, [sg_m], None, [metrics_port, 22])
    b.compute("job-producer", "lambda", None, [], "role-producer", [])
    ext, host = _common_externals(b, f"203.0.113.{rng.randint(2, 250)}/32")
    b.intent(f"worker calls {host}", kind="network", src=w, dst=host, proto="tcp", port=443)
    b.intent(f"worker pushes metrics to the metrics host on {metrics_port}", kind="network", src=w, dst=m, proto="tcp", port=metrics_port)
    b.intent("worker receives jobs from SQS", kind="iam", principal="role-worker", action="sqs:ReceiveMessage", resource=queue, context={})
    b.intent("producer Lambda enqueues jobs", kind="iam", principal="role-producer", action="sqs:SendMessage", resource=queue, context={})
    b.intent("worker stores results in DynamoDB", kind="iam", principal="role-worker", action="dynamodb:PutItem", resource=table, context={})
    b.intent("worker fetches its API token", kind="iam", principal="role-worker", action="secretsmanager:GetSecretValue",
             resource=secret, context={})
    return b


TEMPLATES = {
    "three_tier_web": three_tier_web,
    "serverless_api": serverless_api,
    "data_platform": data_platform,
    "peered_shared_services": peered_shared_services,
    "queue_workers": queue_workers,
}
