"""Closed vocabulary of fault classes. Every diagnosis and every benchmark label uses these names."""

FAULT_CLASSES = {
    # network: security groups and NACLs
    "sg_ingress_block": "destination security group does not allow the inbound connection",
    "sg_egress_block": "source security group does not allow the outbound connection",
    "nacl_ingress_block": "a subnet network ACL drops the request on the way in",
    "nacl_egress_block": "a subnet network ACL drops the request on the way out",
    "nacl_return_block": "a stateless network ACL drops reply traffic on ephemeral ports",
    # network: routing and addressing
    "route_missing_internet": "route table has no usable route to the internet",
    "igw_detached": "internet gateway is not attached to the VPC",
    "no_public_ip": "instance needs a public IP or Elastic IP for this path",
    "lambda_public_subnet": "Lambda function placed in a public subnet (Lambda ENIs never get public IPs)",
    "lambda_not_in_vpc": "Lambda function is not attached to the VPC holding the private resource",
    "nat_misplaced": "NAT gateway sits in a subnet without an internet-gateway route",
    "peering_route_missing": "a route table lacks the route through the VPC peering connection",
    "peering_not_active": "VPC peering connection is not active (pending acceptance or deleted)",
    "peering_missing": "no peering connection exists between the VPCs",
    # network: DNS and host
    "dns_phz_not_associated": "private hosted zone is not associated with the VPC",
    "dns_support_disabled": "VPC has enableDnsSupport turned off",
    "service_not_listening": "nothing is listening on the destination port",
    # IAM
    "iam_action_missing": "no identity policy allows the action",
    "iam_resource_mismatch": "an identity policy allows the action but on the wrong resource ARN",
    "iam_condition_mismatch": "an identity policy Allow has a Condition the request does not satisfy",
    "iam_policy_not_attached": "the policy that grants access exists but is not attached",
    "iam_explicit_deny": "an explicit Deny in an identity policy",
    "iam_boundary_block": "the permissions boundary does not allow the action",
    "scp_block": "a service control policy denies or does not allow the action",
    "resource_policy_deny": "an explicit Deny in the resource (bucket/key) policy",
    "cross_account_resource_policy_missing": "cross-account access without a matching resource-policy grant",
    "kms_key_policy_block": "the KMS key policy does not allow the caller to use the key",
    "endpoint_policy_block": "the VPC endpoint policy does not allow the request",
}

NETWORK_CLASSES = {k for k in FAULT_CLASSES if not k.startswith(("iam_", "scp_", "resource_", "cross_", "kms_", "endpoint_"))}
IAM_CLASSES = set(FAULT_CLASSES) - NETWORK_CLASSES
