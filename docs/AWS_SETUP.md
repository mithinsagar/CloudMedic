# Running the AWS validation experiments

Everything in the main evaluation runs offline. Two optional experiments check the formal models against AWS itself:

| Experiment | What it does | Cost | Creates resources? |
|---|---|---|---|
| IAM fidelity (`cloudmedic.aws.iam_fidelity`) | Compares the IAM model with `iam:SimulateCustomPolicy` on 400 random policy cases | Free | No |
| Live network (`cloudmedic.aws.live_network`) | Builds a throwaway VPC with three `t3.micro` instances, injects 10 SG/NACL faults, probes real TCP connections | Free-tier eligible; otherwise a few US cents | Yes, all tagged `cloudmedic-live=true` and deleted at the end |
| Account import (`cloudmedic.aws.importer`) | Reads an account's config into a snapshot (read-only) | Free | No |

## 1. Create a dedicated IAM user (5 minutes, AWS console)

Do not use root credentials.

1. **Billing safety first:** Billing and Cost Management, then Budgets, then create a *zero spend budget* with email alerts.
2. IAM, then Users, then *Create user*, name `cloudmedic`. Do not give console access.
3. Attach permissions: *Create inline policy*, JSON tab, paste [`aws-validation-policy.json`](aws-validation-policy.json).
   It allows only what the two experiments need, only `t3.micro` instances, only in `us-east-1`, and only the one IAM role
   the harness creates. For the account importer, also attach the AWS managed policy `ReadOnlyAccess`.
4. On the user, open *Security credentials*, then *Create access key*, then *Command Line Interface*. Copy both keys.

## 2. Configure a local profile

```bash
.venv/bin/pip install awscli   # or: brew install awscli
aws configure --profile cloudmedic     # paste keys, region us-east-1, output json
aws sts get-caller-identity --profile cloudmedic
```

The last command prints your user ARN, e.g. `arn:aws:iam::123456789012:user/cloudmedic`.

## 3. Run

```bash
# IAM model fidelity (free, no resources)
.venv/bin/python -m cloudmedic.aws.iam_fidelity --profile cloudmedic --caller-arn arn:aws:iam::123456789012:user/cloudmedic --n 400

# Live network validation (about 30 to 45 minutes; cleans up after itself)
.venv/bin/python -m cloudmedic.aws.live_network --profile cloudmedic --region us-east-1

# If a run is interrupted, remove anything left behind
.venv/bin/python -m cloudmedic.aws.live_network --profile cloudmedic --region us-east-1 --cleanup

# Rebuild tables and the paper with the new numbers
.venv/bin/python scripts/make_report.py && (cd paper && tectonic -X compile main.tex)
```

## 4. Afterwards

Deactivate or delete the access key in the IAM console when you are done.
