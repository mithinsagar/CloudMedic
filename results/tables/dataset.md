| Fault class | family | test labels |
|---|---|---|
| cross_account_resource_policy_missing | IAM | 10 |
| dns_phz_not_associated | network | 11 |
| dns_support_disabled | network | 11 |
| endpoint_policy_block | IAM | 10 |
| iam_action_missing | IAM | 15 |
| iam_boundary_block | IAM | 21 |
| iam_condition_mismatch | IAM | 11 |
| iam_explicit_deny | IAM | 19 |
| iam_policy_not_attached | IAM | 14 |
| iam_resource_mismatch | IAM | 13 |
| igw_detached | network | 11 |
| kms_key_policy_block | IAM | 12 |
| lambda_public_subnet | network | 10 |
| nacl_egress_block | network | 17 |
| nacl_ingress_block | network | 22 |
| nacl_return_block | network | 17 |
| nat_misplaced | network | 10 |
| no_public_ip | network | 12 |
| peering_not_active | network | 10 |
| peering_route_missing | network | 10 |
| resource_policy_deny | IAM | 18 |
| route_missing_internet | network | 15 |
| scp_block | IAM | 17 |
| service_not_listening | network | 13 |
| sg_egress_block | network | 14 |
| sg_ingress_block | network | 17 |

Test split: 310 scenarios (260 single-fault, 50 multi-fault), 26 fault classes, 5 architectures, seeds 100-111. Dev split: 88 scenarios (seeds 0-2).
Candidate faults generated: 2934; dropped because the intent still worked (V1): 47; reference fix invalid (V2): 0; surface drift (V3): 0; multi-fault pairs rejected as not jointly necessary (V4): 0.
Label/evaluator agreement on the valid pool: 100.0%; on the released test split: 99.4%.
Difficulty: {'L2': 136, 'L1': 124, 'L3': 50}. Templates: {'data_platform': 48, 'serverless_api': 71, 'three_tier_web': 58, 'peered_shared_services': 66, 'queue_workers': 67}.
