import copy
import json
import random
from pathlib import Path

import pytest

from cloudmedic.bench.mutations import candidate_faults
from cloudmedic.bench.templates import TEMPLATES, Builder
from cloudmedic.edits import apply_edits
from cloudmedic.expansion import fixed_universe, surface
from cloudmedic.iam import evaluate_request
from cloudmedic.intents import evaluate_intent
from cloudmedic.network import evaluate_flow, nacl_decision, nacl_range
from cloudmedic.policy import conditions_hold, wild_match
from cloudmedic.repair import repair


# ------------------------------------------------------------------ policy language

def test_wildcards():
    assert wild_match("s3:Get*", "s3:getobject", ignore_case=True)
    assert wild_match("arn:aws:s3:::b/*", "arn:aws:s3:::b/x/y.csv")
    assert not wild_match("arn:aws:s3:::b/*", "arn:aws:s3:::b")
    assert wild_match("arn:aws:s3:::b?", "arn:aws:s3:::b1")


def test_negated_condition_with_missing_key_matches():
    st = {"Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-1"}}}
    assert conditions_hold(st, {})            # AWS: negated operator + absent key -> true
    assert not conditions_hold({"Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}, {})
    assert conditions_hold({"Condition": {"StringEqualsIfExists": {"k": "v"}}}, {})
    assert conditions_hold({"Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}, {"aws:SourceIp": "10.1.2.3"})


# ------------------------------------------------------------------ network fixtures

def two_subnet_vpc(tight=False):
    b = Builder(random.Random(1), account="111111111111")
    v = b.vpc("v", "10.0.0.0/16")
    if tight:
        acl_a = b.nacl("a", v, [{"rule": 100, "proto": "tcp", "from": 1024, "to": 65535, "cidr": "0.0.0.0/0", "action": "allow"}],
                       [{"rule": 100, "proto": "tcp", "from": 5432, "to": 5432, "cidr": "10.0.2.0/24", "action": "allow"}])
        acl_b = b.nacl("b", v, [{"rule": 100, "proto": "tcp", "from": 5432, "to": 5432, "cidr": "10.0.1.0/24", "action": "allow"}],
                       [{"rule": 100, "proto": "tcp", "from": 1024, "to": 65535, "cidr": "10.0.1.0/24", "action": "allow"}])
    else:
        acl_a = acl_b = b.nacl("d", v)
    rt = b.route_table("rt", v)
    sa = b.subnet("a", v, "10.0.1.0/24", rt, acl_a)
    sb = b.subnet("b", v, "10.0.2.0/24", rt, acl_b)
    sg_app = b.sg("app", v, [])
    sg_db = b.sg("db", v, [{"proto": "tcp", "from": 5432, "to": 5432, "sg": sg_app}])
    app = b.compute("app", "ec2", sa, [sg_app], None, [])
    db = b.compute("db", "rds", sb, [sg_db], None, [5432])
    return b.snap, app, db, acl_a, acl_b, sg_db


def test_healthy_flow_and_sg_reference():
    snap, app, db, *_ = two_subnet_vpc(tight=True)
    assert evaluate_flow(snap, app, db, "tcp", 5432).ok
    assert not evaluate_flow(snap, db, app, "tcp", 22).ok


def test_nacl_first_match_and_implicit_deny():
    nacl = {"ingress": [{"rule": 200, "proto": "tcp", "from": 22, "to": 22, "cidr": "0.0.0.0/0", "action": "allow"},
                        {"rule": 100, "proto": "tcp", "from": 22, "to": 22, "cidr": "1.2.3.4/32", "action": "deny"}]}
    assert nacl_decision(nacl, "ingress", "tcp", 22, "1.2.3.4")[0] is False   # lower number wins
    assert nacl_decision(nacl, "ingress", "tcp", 22, "5.6.7.8")[0] is True
    assert nacl_decision(nacl, "ingress", "tcp", 80, "5.6.7.8") == (False, None)  # implicit deny


def test_nacl_partial_ephemeral_coverage_is_intermittent():
    snap, app, db, acl_a, acl_b, _ = two_subnet_vpc(tight=True)
    snap["compute"][app]["ephemeral"] = [1024, 65535]
    snap["nacls"][acl_a]["ingress"][0]["from"] = 32768
    frac, _ = nacl_range(snap["nacls"][acl_a], "ingress", "tcp", 1024, 65535, snap["compute"][db]["private_ip"])
    assert 0 < frac < 1
    r = evaluate_flow(snap, app, db, "tcp", 5432)
    assert r.symptom == "intermittent_timeout"
    assert any(c.fault_class == "nacl_return_block" for c in r.failing)


def test_same_subnet_traffic_bypasses_nacl():
    snap, app, db, acl_a, acl_b, _ = two_subnet_vpc(tight=True)
    snap["compute"][db]["subnet"] = snap["compute"][app]["subnet"]
    snap["compute"][db]["private_ip"] = "10.0.1.99"
    snap["nacls"][acl_a]["egress"] = []
    assert evaluate_flow(snap, app, db, "tcp", 5432).ok


def test_full_path_finds_masked_faults():
    snap, app, db, acl_a, acl_b, sg_db = two_subnet_vpc(tight=True)
    snap["security_groups"][sg_db]["ingress"] = []
    snap["compute"][db]["listening"] = []
    classes = {c.fault_class for c in evaluate_flow(snap, app, db, "tcp", 5432).failing}
    assert {"sg_ingress_block", "service_not_listening"} <= classes


def test_connection_refused_vs_timeout():
    snap, app, db, *_ = two_subnet_vpc()
    snap["compute"][db]["listening"] = []
    assert evaluate_flow(snap, app, db, "tcp", 5432).symptom == "connection_refused"


@pytest.mark.parametrize("name", list(TEMPLATES))
def test_templates_are_healthy(name):
    for seed in range(5):
        b = TEMPLATES[name](random.Random(seed))
        for it in b.intents:
            assert evaluate_intent(b.snap, it).ok, it


def test_lambda_never_uses_public_ip():
    b = TEMPLATES["serverless_api"](random.Random(3))
    fn = next(k for k, c in b.snap["compute"].items() if c["kind"] == "lambda")
    pub = next(k for k, s in b.snap["subnets"].items() if s["name"] == "public-a")
    s, _, errs = apply_edits(b.snap, [{"op": "compute_set_subnet", "compute": fn, "subnet": pub}])
    assert not errs
    host = next(it for it in b.intents if it["kind"] == "network" and it["port"] == 443)
    r = evaluate_intent(s, host)
    assert [c.fault_class for c in r.failing] == ["lambda_public_subnet"]


def test_peering_needs_return_route():
    b = TEMPLATES["peered_shared_services"](random.Random(2))
    it = b.intents[1]
    rt = next(k for k, r in b.snap["route_tables"].items() if r["name"] == "shared-rt")
    s = copy.deepcopy(b.snap)
    s["route_tables"][rt]["routes"] = s["route_tables"][rt]["routes"][:1]
    r = evaluate_intent(s, it)
    assert any(c.id == "return_route" and c.fault_class == "peering_route_missing" for c in r.failing)


# ------------------------------------------------------------------ IAM

def iam_snap():
    return TEMPLATES["data_platform"](random.Random(5))


def test_explicit_deny_beats_allow():
    b = iam_snap()
    it = b.intents[0]
    b.snap["iam"]["policies"]["pol-analyst"]["Statement"].append(
        {"Sid": "D", "Effect": "Deny", "Action": "s3:*", "Resource": "*"})
    r = evaluate_intent(b.snap, it)
    assert r.failing[0].fault_class == "iam_explicit_deny"


def test_boundary_limits_identity():
    b = iam_snap()
    b.snap["iam"]["policies"]["pol-dev-boundary"]["Statement"][0]["Action"] = ["athena:*"]
    r = evaluate_intent(b.snap, b.intents[0])
    assert any(c.fault_class == "iam_boundary_block" for c in r.failing)


def test_cross_account_needs_both_sides():
    b = iam_snap()
    it = b.intents[3]
    assert evaluate_intent(b.snap, it).ok
    lake = next(a for a, r in b.snap["resources"].items() if r["type"] == "s3_bucket")
    b.snap["resources"][lake]["policy"]["Statement"] = b.snap["resources"][lake]["policy"]["Statement"][1:]
    assert [c.fault_class for c in evaluate_intent(b.snap, it).failing] == ["cross_account_resource_policy_missing"]


def test_kms_delegation_requires_identity_permission():
    b = iam_snap()
    it = b.intents[0]
    b.snap["iam"]["policies"]["pol-analyst"]["Statement"] = b.snap["iam"]["policies"]["pol-analyst"]["Statement"][:2]
    r = evaluate_intent(b.snap, it)
    assert r.symptom == "access_denied_kms" and r.failing[0].id == "kms_identity"


def test_scp_region_lock():
    b = iam_snap()
    r = evaluate_request(b.snap, "role-analyst", "s3:ListBucket", b.intents[1]["resource"], {"aws:RequestedRegion": "ap-south-1"})
    assert any(c.fault_class == "scp_block" for c in r.failing)


# ------------------------------------------------------------------ edits

def test_edits_reject_hallucinated_resources():
    snap, app, db, *_ = two_subnet_vpc()
    _, applied, errs = apply_edits(snap, [{"op": "sg_add_rule", "sg": "sg-doesnotexist", "direction": "ingress", "proto": "tcp",
                                           "from": 1, "to": 1, "cidr": "0.0.0.0/0"},
                                          {"op": "teleport", "x": 1}])
    assert not applied and len(errs) == 2


def test_edits_do_not_mutate_input():
    snap, app, db, *_ = two_subnet_vpc()
    before = json.dumps(snap, sort_keys=True)
    apply_edits(snap, [{"op": "compute_listen", "compute": db, "proto": "tcp", "port": 9999}])
    assert json.dumps(snap, sort_keys=True) == before


# ------------------------------------------------------------------ repair

def test_repair_prefers_narrow_fix():
    snap, app, db, acl_a, acl_b, sg_db = two_subnet_vpc()
    snap["security_groups"][sg_db]["ingress"] = []
    rep = repair(snap, {"kind": "network", "src": app, "dst": db, "proto": "tcp", "port": 5432})
    assert rep.verified and rep.stats["total_gained"] == 0
    assert rep.edits[0]["op"] == "sg_add_rule" and rep.edits[0].get("cidr") != "0.0.0.0/0"


def test_repair_handles_two_faults():
    snap, app, db, acl_a, acl_b, sg_db = two_subnet_vpc(tight=True)
    snap["security_groups"][sg_db]["ingress"] = []
    snap["nacls"][acl_b]["egress"] = []
    rep = repair(snap, {"kind": "network", "src": app, "dst": db, "proto": "tcp", "port": 5432})
    assert rep.verified
    fixed, _, _ = apply_edits(snap, rep.edits)
    assert evaluate_flow(fixed, app, db, "tcp", 5432).ok


# ------------------------------------------------------------------ benchmark construction

def test_reference_fixes_restore_healthy_surface():
    rng = random.Random(0)
    for name, fn in TEMPLATES.items():
        b = fn(random.Random(42))
        uni = fixed_universe(b.snap)
        healthy = surface(b.snap, uni)
        for it in b.intents[:2]:
            trace = evaluate_intent(b.snap, it)
            for f in candidate_faults(b.snap, it, trace, rng)[:6]:
                if evaluate_intent(f["snap"], it).ok:
                    continue
                fixed, _, errs = apply_edits(f["snap"], f["reference_fix"])
                assert not errs and surface(fixed, uni) == healthy, (name, f["operator"])


def test_dataset_card_exists_if_generated():
    card = Path("data/test_card.json")
    if card.exists():
        c = json.loads(card.read_text())
        assert c["n_scenarios"] > 0 and set(c["per_class"]) <= set(__import__("cloudmedic.taxonomy", fromlist=["x"]).FAULT_CLASSES)
