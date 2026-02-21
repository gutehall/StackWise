# Using StackWise with AWS profiles

If you use **profiles** (e.g. `~/.aws/credentials` and `~/.aws/config`), you can assume the `stackwise` role via a named profile.

## 1. Deploy the role

Deploy the CloudFormation stack with the principal that may assume the role (your IAM user or the account root):

```bash
# Replace ACCOUNT_ID and optionally USERNAME with your account and IAM user
aws cloudformation create-stack \
  --stack-name stackwise-role \
  --template-body file://docs/stackwise-role.yaml \
  --parameters ParameterKey=TrustedPrincipalArn,ParameterValue=arn:aws:iam::ACCOUNT_ID:user/USERNAME \
  --capabilities CAPABILITY_NAMED_IAM
```

To allow any identity in the account to assume the role:

```bash
aws cloudformation create-stack \
  --stack-name stackwise-role \
  --template-body file://docs/stackwise-role.yaml \
  --parameters "ParameterKey=TrustedPrincipalArn,ParameterValue=arn:aws:iam::ACCOUNT_ID:root" \
  --capabilities CAPABILITY_NAMED_IAM
```

## 2. Add a profile that assumes the role

In **`~/.aws/config`** add a profile that uses your existing credentials to assume the `stackwise` role:

```ini
[profile stackwise]
role_arn = arn:aws:iam::ACCOUNT_ID:role/stackwise
source_profile = YOUR_BASE_PROFILE
region = eu-west-1
```

- Replace `ACCOUNT_ID` with your AWS account ID.
- Replace `YOUR_BASE_PROFILE` with the profile name that has credentials in `~/.aws/credentials` (the one that is allowed to assume the role).

If you use a default profile and don't name it, it's often `[default]` in config; in that case you can use `source_profile = default`.

## 3. Use the profile

```bash
aws sts get-caller-identity --profile stackwise
# or run your app with:
AWS_PROFILE=stackwise python -m stackwise ...
```

Your base profile (in credentials/config) must have `sts:AssumeRole` permission for the `stackwise` role; the CloudFormation parameter `TrustedPrincipalArn` defines who is allowed to assume it.
