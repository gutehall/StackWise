# StackWise

AWS infrastructure scanner with local AI-powered recommendations.

Scans your AWS account, analyzes the infrastructure using a local LLM (via Ollama), and generates engineering reports — all without sending data to the cloud.

## Prerequisites

- Python 3.11+
- AWS credentials configured (SSO, profile, or environment variables)
- [Ollama](https://ollama.com) installed and running (optional — falls back to rules-only analysis)

For PDF report output, install WeasyPrint system dependencies:

- **macOS**: `brew install pango cairo libffi`
- **Debian/Ubuntu**: `apt-get install libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libffi-dev libgdk-pixbuf2.0-0`

## Setup

```bash
git clone https://github.com/gutehall/StackWise.git && cd StackWise
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

To use Ollama for AI-enriched recommendations:

```bash
ollama pull qwen2.5:14b
```

## Usage

### All-in-one

```bash
stackwise run --profile my-aws-profile --regions eu-west-1,us-east-1
```

### Step by step

```bash
# 1. Scan AWS resources
stackwise scan --profile my-aws-profile --regions eu-west-1,us-east-1 --modules compute

# 2. Analyze findings (rules + optional LLM)
stackwise analyze --profile my-aws-profile

# 3. Generate report
stackwise report --type engineering --format html
```

### Other commands

```bash
stackwise list-scans          # show previous scan snapshots
stackwise diff                # compare latest scan with previous (drift detection)
stackwise --help              # full CLI reference
```

### CI/CD integration

Output JSON for pipelines:

```bash
stackwise run --format json
# Writes stackwise-engineering-{account}-{date}.json with findings and recommendations
```

Diff output as JSON:

```bash
stackwise diff --format json
# Outputs drift data to stdout for pipeline parsing
```

See [docs/json-output-schema.md](docs/json-output-schema.md) for the full JSON schema and CI examples.

Suppress specific rules:

```bash
stackwise analyze --suppress CMP-001,DAT-002
# Or: STACKWISE_SUPPRESSED_RULES=CMP-001,DAT-002 stackwise analyze
```

## Cost

Every scanner call is a free control-plane API (`Describe*`/`List*`/`Get*`) except one:
Cost Explorer's `GetCostAndUsage` bills **$0.01 per request**. The `cost` module (enabled by
default) makes exactly one such call per scan, to populate the "Cost by Service" chart. Skip it
with:

```bash
stackwise scan --skip-cost-explorer
# Or: STACKWISE_SKIP_COST_EXPLORER=true stackwise scan
```

## AWS Permissions

Use one of:

- **Attach policy to an existing role:** use the minimal read-only policy in [docs/iam-policy.json](docs/iam-policy.json).
- **Create a dedicated role:** deploy the CloudFormation stack [docs/stackwise-role.yaml](docs/stackwise-role.yaml). It creates the IAM role `stackwise` and attaches the read-only policy. You must pass `TrustedPrincipalArn` (e.g. your IAM user ARN or `arn:aws:iam::ACCOUNT_ID:root`). For profile-based setup (credentials/config), see [docs/aws-profile-setup.md](docs/aws-profile-setup.md).

## Docker

```bash
docker run --rm -v ~/.aws:/root/.aws:ro -v $(pwd)/reports:/reports \
  ghcr.io/gutehall/stackwise:latest run --profile default -o /reports
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
```
