# Deploying StackWise on EC2 or ECS

This guide covers deploying StackWise as a scheduled job on **Amazon EC2** or **Amazon ECS**. Both options use IAM roles for credentials (no AWS profile files required) and are suitable for automated scans in CI/CD or scheduled infrastructure audits.

> **Fully automated, single-instance option:** [`docs/stackwise-ec2.yaml`](stackwise-ec2.yaml) is a one-shot CloudFormation template — one EC2 instance, IAM role, and a UserData script that installs Python, clones StackWise, installs Ollama, pulls the model, and sets up a systemd timer, all in one launch. No Docker, no manual steps. Deploy with:
>
> ```bash
> aws cloudformation create-stack \
>   --stack-name stackwise \
>   --template-body file://docs/stackwise-ec2.yaml \
>   --capabilities CAPABILITY_IAM \
>   --parameters ParameterKey=VpcId,ParameterValue=vpc-xxxxxxxx \
>                ParameterKey=SubnetId,ParameterValue=subnet-xxxxxxxx
> ```
>
> The manual EC2/ECS walkthroughs below are for customizing beyond what that template covers (Docker-based deploys, ECS/Fargate, EFS/S3 persistence options).

## Overview

| Aspect | EC2 | ECS |
|--------|-----|-----|
| **Best for** | Long-running instances, cron-style jobs | Serverless-style, task-based runs |
| **Credentials** | Instance profile (IAM role) | Task role |
| **Scheduling** | cron, systemd timer, or external scheduler | EventBridge + ECS RunTask |
| **Persistence** | EBS volume or instance store | EFS or S3 (export reports) |

---

## Prerequisites

1. **IAM role** with stackwise read-only permissions. Deploy the CloudFormation stack:

   ```bash
   aws cloudformation create-stack \
     --stack-name stackwise-role \
     --template-body file://docs/stackwise-role.yaml \
     --parameters "ParameterKey=TrustedPrincipalArn,ParameterValue=arn:aws:iam::ACCOUNT_ID:root" \
     --capabilities CAPABILITY_NAMED_IAM
   ```

2. **Docker image** from GitHub Container Registry:

   ```
   ghcr.io/gutehall/stackwise:latest
   ```

   Or build locally:

   ```bash
   docker build -t stackwise:latest .
   ```

---

## EC2 Deployment

### 1. Launch an EC2 instance with the stackwise role

- **AMI**: Amazon Linux 2023 or Ubuntu 22.04
- **Instance type**: `t3.small` or larger (more regions = more memory for parallel scans)
- **IAM instance profile**: Attach a role that has `sts:AssumeRole` for the `stackwise` role, or attach the `stackwise` role directly if the stack trusts the EC2 role

### 2. Trust the EC2 instance profile

Update the CloudFormation stack to allow the EC2 instance profile role to assume `stackwise`:

```yaml
# In stackwise-role.yaml, TrustedPrincipalArn could be:
# arn:aws:iam::ACCOUNT_ID:role/ec2-stackwise-role
```

Or create an EC2 role that includes the stackwise policy (see [docs/iam-policy.json](iam-policy.json)).

### 3. Install Docker and run stackwise

```bash
# Install Docker (Amazon Linux 2023)
sudo yum install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker ec2-user

# Create directories for data and reports
sudo mkdir -p /opt/stackwise/data /opt/stackwise/reports
sudo chown ec2-user:ec2-user /opt/stackwise/data /opt/stackwise/reports

# Run scan (uses instance profile; no --profile needed)
docker run --rm \
  -v /opt/stackwise/data:/data \
  -v /opt/stackwise/reports:/reports \
  -e STACKWISE_DATA_DIR=/data \
  -e AWS_DEFAULT_REGION=eu-west-1 \
  ghcr.io/gutehall/stackwise:latest \
  run --regions eu-west-1,us-east-1 -o /reports
```

### 4. Schedule with cron

```bash
# Edit crontab
crontab -e

# Run daily at 2 AM UTC
0 2 * * * docker run --rm -v /opt/stackwise/data:/data -v /opt/stackwise/reports:/reports -e STACKWISE_DATA_DIR=/data -e STACKWISE_REGIONS=eu-west-1,us-east-1 ghcr.io/gutehall/stackwise:latest run -o /reports >> /var/log/stackwise.log 2>&1
```

### 5. Optional: systemd timer

Create `/etc/systemd/system/stackwise.service`:

```ini
[Unit]
Description=stackwise AWS infrastructure scan
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/docker run --rm \
  -v /opt/stackwise/data:/data \
  -v /opt/stackwise/reports:/reports \
  -e STACKWISE_DATA_DIR=/data \
  -e STACKWISE_REGIONS=eu-west-1,us-east-1 \
  ghcr.io/gutehall/stackwise:latest run -o /reports
```

Create `/etc/systemd/system/stackwise.timer`:

```ini
[Unit]
Description=Run stackwise daily

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:

```bash
sudo systemctl enable stackwise.timer
sudo systemctl start stackwise.timer
```

---

## ECS Deployment

### 1. Create ECS cluster and task definition

**Task definition** (`stackwise-task.json`):

```json
{
  "family": "stackwise",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT_ID:role/stackwise",
  "containerDefinitions": [
    {
      "name": "stackwise",
      "image": "ghcr.io/gutehall/stackwise:latest",
      "essential": true,
      "environment": [
        { "name": "STACKWISE_DATA_DIR", "value": "/data" },
        { "name": "STACKWISE_REGIONS", "value": "eu-west-1,us-east-1" }
      ],
      "command": ["run", "-o", "/reports"],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/stackwise",
          "awslogs-region": "eu-west-1"
        }
      },
      "mountPoints": [
        { "sourceVolume": "reports", "containerPath": "/reports" }
      ]
    }
  ],
  "volumes": [
    {
      "name": "reports",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-xxxxxxxx",
        "rootDirectory": "/stackwise/reports"
      }
    }
  ]
}
```

**Notes:**

- `taskRoleArn`: Use the `stackwise` role ARN from the CloudFormation output.
- `executionRoleArn`: Standard ECS task execution role (pull images, write logs).
- For reports persistence, use an **EFS volume** or **S3** (see below).

### 2. EFS for report persistence (optional)

Create an EFS file system and mount it in the task:

```bash
# Create EFS
aws efs create-file-system --performance-mode generalPurpose --throughput-mode bursting

# Create mount target in your VPC subnets
aws efs create-mount-target --file-system-id fs-xxxxxxxx --subnet-id subnet-xxx --security-groups sg-xxx
```

Ensure the ECS task's security group allows NFS (port 2049) to the EFS mount targets.

### 3. S3 for report export (alternative)

If you prefer S3 over EFS, run stackwise without a reports volume and add a post-task step to upload:

```json
"command": ["run", "--format", "json", "-o", "/tmp/reports"]
```

Then use a Lambda or Step Functions to copy from the container's ephemeral storage to S3. Alternatively, run a two-step ECS task: first container runs `stackwise run`, second container runs `aws s3 sync /reports s3://your-bucket/stackwise/`.

### 4. Schedule with EventBridge

Create an EventBridge rule to run the task on a schedule:

```bash
# Create rule (daily at 2 AM UTC)
aws events put-rule \
  --name stackwise-daily \
  --schedule-expression "cron(0 2 * * ? *)" \
  --state ENABLED

# Add ECS task as target
aws events put-targets \
  --rule stackwise-daily \
  --targets '[
    {
      "Id": "1",
      "Arn": "arn:aws:ecs:eu-west-1:ACCOUNT_ID:cluster/stackwise",
      "RoleArn": "arn:aws:iam::ACCOUNT_ID:role/events-ecs-role",
      "EcsParameters": {
        "TaskDefinitionArn": "arn:aws:ecs:eu-west-1:ACCOUNT_ID:task-definition/stackwise:1",
        "TaskCount": 1,
        "LaunchType": "FARGATE",
        "NetworkConfiguration": {
          "awsvpcConfiguration": {
            "Subnets": ["subnet-xxx"],
            "SecurityGroups": ["sg-xxx"],
            "AssignPublicIp": "DISABLED"
          }
        }
      }
    }
  ]'
```

The IAM role `events-ecs-role` needs `ecs:RunTask` and `iam:PassRole` for the task and execution roles.

### 5. Run once (manual)

```bash
aws ecs run-task \
  --cluster stackwise \
  --task-definition stackwise \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=DISABLED}"
```

---

## Environment variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AWS_PROFILE` | Named profile (if not using IAM role) | `stackwise` |
| `AWS_DEFAULT_REGION` | Default region for SDK | `eu-west-1` |
| `STACKWISE_DATA_DIR` | Scan DB and metadata directory | `/data` |
| `STACKWISE_REGIONS` | Comma-separated regions to scan | `eu-west-1,us-east-1` |
| `STACKWISE_MODEL` | Ollama model (if using LLM) | `qwen3:14b` |
| `OLLAMA_HOST` | Ollama API URL (if using LLM) | `http://localhost:11434` |
| `STACKWISE_SCAN_MAX_WORKERS` | Parallel regions per scanner | `4` |

---

## Rules-only vs. LLM analysis

By default, stackwise uses **Ollama** for AI-enriched recommendations when available. On EC2/ECS:

- **Rules-only**: No Ollama. Add `--engine rules-only` to the command or ensure Ollama is not installed. Fastest, no extra dependencies.
- **With Ollama**: Run Ollama as a sidecar or on the same host. Requires more memory (e.g. 4 GB+ for `qwen3:14b`). For ECS, use a multi-container task with an Ollama sidecar and `OLLAMA_HOST=http://localhost:11434`.

For most scheduled/CI use cases, **rules-only** is sufficient and keeps resource usage low.

---

## Security considerations

- Use **least-privilege** IAM roles. The policy in [iam-policy.json](iam-policy.json) is read-only.
- Store reports in a **private** S3 bucket or EFS with restricted access.
- Enable **VPC endpoints** for ECS/Fargate if running in private subnets to avoid NAT gateway costs.
- Consider **Secrets Manager** for any API keys if you add integrations later.

---

## Troubleshooting

| Issue | Check |
|-------|-------|
| `Failed to get AWS account ID` | IAM role attached? VPC endpoint for STS if in private subnet? |
| `No scan found` | `STACKWISE_DATA_DIR` set? Volume mounted correctly? |
| Out of memory | Reduce `STACKWISE_REGIONS` or `STACKWISE_SCAN_MAX_WORKERS` |
| Slow scans | Increase `STACKWISE_SCAN_MAX_WORKERS` (default 4) |
