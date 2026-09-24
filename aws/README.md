# Scanner deployment reference

See the [repository README](../README.md) to get started — prerequisites, the
variables you must set, and a first scan. This document is the reference for
what the stack creates and how to operate it.

## Resources this creates

`<env>` is `var.environment`, default `dev`.

| Resource | Name |
|---|---|
| Scan runtime role | `ami-scanner-<env>-ecs-task-role` |
| Instance role | `ami-scanner-<env>-ecs-instance-role` |
| Instance profile | `ami-scanner-<env>-ecs-instance-profile` |
| Launch template | `ami-scanner-<env>-*` |
| Auto Scaling group | `ami-scanner-<env>-asg` |
| Security group | `ami-scanner-<env>-sg` |
| Scan queue | `ami-scanner-<env>-scan-queue` |
| S3 results bucket | `ami-scanner-<env>-results-<account-id>` |
| CloudWatch log group | `/aws/ec2/ami-scanner-<env>` |
| API token secret | `ami-scanner-<env>-rl-api-token-*`, unless you supply your own |

Conditional on the options that create them: a deploy-time role
(`-deploy-role`), an SNS topic (`-alerts`), an EventBridge rule
(`-ami-available`) with its queue policy, and — with `enable_scan_schedule` —
a dispatch launch template, its instance profile, and the dispatcher and
scheduler roles.

VPC and subnets are yours; pass them as `vpc_id` / `subnet_ids`.

## EC2 capacity

| Variable | Default | Purpose |
|---|---|---|
| `instance_type` | `t3.medium` | Scanner instance size. Raise it for large AMIs — the scan volume is mounted on the instance and extraction is CPU-bound. |
| `asg_min_size` | `0` | Scale to zero when idle. |
| `asg_max_size` | `2` | Ceiling on concurrent scan hosts. |
| `asg_desired_capacity` | `1` | Instances at apply time. |

Instances boot from `scanner_ami_id` and require IMDSv2. The instance role
carries `AmazonSSMManagedInstanceCore`, so you can open a shell on a scan host
with `aws ssm start-session` without exposing SSH.

The group scales on **backlog per instance** — outstanding scan messages
divided by in-service instances — tracking a target of **1.0**: one queued
asset per instance. Above that it adds capacity, up to `asg_max_size`;
as the queue drains it returns to `asg_min_size`. The daemon scans one asset at
a time, which is what makes 1.0 the break-even point.

With `asg_min_size = 0` the first scan after an idle period waits for an
instance to boot.

## Resource tags

Every resource the stack creates inherits `local.common_tags`, and the launch
template repeats them under `tag_specifications` so instances and their root
volumes are tagged at launch.

Four keys the stack sets itself:

| Tag | Value |
|---|---|
| `Name` | `local.name_prefix`, overridden per resource |
| `Project` | `var.tag_project`, default `detect-ami-scanner` |
| `Method` | `ec2` |
| `ManagedBy` | `terraform` |

Everything else comes from **`var.resource_tags`**, a free-form `map(string)`,
empty by default:

```hcl
resource_tags = {
  Environment = "prod"
  Owner       = "security"
}
```

Set whatever your account's tag policy and cost-allocation scheme require.
`Project` and `ManagedBy` are not safe to redefine: `Project` gates the task
role's `ec2:AttachVolume` / `ec2:DetachVolume` grant, and `ManagedBy`
distinguishes a terraform-created resource from a scanner-created one.

An `Environment` key in `resource_tags` is unrelated to `var.environment`: the
latter feeds `local.name_prefix` and so appears in every resource *name*.

### Tags on resources the scanner creates at runtime

The snapshots and volumes the scanner creates mid-scan are not terraform
resources, so they cannot inherit `local.common_tags`. The same set reaches the
scanner as `SCANNER_AWS_RESOURCE_TAGS` — comma-separated `Key=Value` pairs —
and the scanner merges your tags underneath its own. Tag values are escaped for
the systemd unit that carries them; avoid `%` in a value if you can.

`scanner:managed=true` is always added and cannot be overridden. The task
policy gates `ec2:CreateSnapshot` and `ec2:CreateVolume` on it as a request
tag, and `DeleteSnapshot` refuses to delete any snapshot lacking it, so
overriding it would make scan resources either uncreatable or undeletable.

Tags are **not** copied from the AMI under scan. A scratch volume is the
scanner's resource, not a derivative of the target, and inheriting a
production AMI's owner or cost-centre would misattribute it.

## Elevated privileges required

The scanner runs as **root** on the instance. That is required to attach the
per-scan EBS volume and run the `mount(2)` / `umount(2)` syscalls a scan
depends on. This is kernel-level access on the scanner instance, not an AWS
IAM grant — separate from, and far broader than, the task role below.

Treat the scanner instances as sensitive: they are dedicated to scanning and
should not be shared with other workloads.

## Task role scoping

The scan role grants only what a scan needs, and scopes every destructive
action by tag. Everything the scanner creates carries `scanner:managed=true`.

| Statement | Grant |
|---|---|
| `DiscoverAssets` | `Describe*`, read-only and unscoped |
| `PreflightPermissionCheck` | `sts:GetCallerIdentity` and `iam:SimulatePrincipalPolicy`, so a missing grant surfaces at startup rather than mid-scan |
| `CreateTaggedSnapshot` | `ec2:CreateSnapshot` on `snapshot/*`, only when the request tags `scanner:managed=true` |
| `SnapshotSourceVolume` | `ec2:CreateSnapshot` on `volume/*`, unconditional — the source-volume leg |
| `CopySourceSnapshot` | `ec2:CopySnapshot`, unconditional |
| `TagOnCreate` | `ec2:CreateTags`, only as part of a `CreateSnapshot` or `CopySnapshot` call |
| `CreateTaggedVolume` | `ec2:CreateVolume` on `volume/*`, only when the request tags `scanner:managed=true` |
| `CreateVolumeFromSnapshot` | `ec2:CreateVolume` on `snapshot/*`, unconditional — the source-snapshot leg |
| `TagVolumeOnCreate` | `ec2:CreateTags` on `volume/*`, only as part of a `CreateVolume` call |
| `AttachDetachOwnVolumes` | Attach/Detach on volumes tagged `scanner:managed=true` |
| `AttachDetachOnScannerInstances` | Attach/Detach on instances tagged with this stack's `Project` |
| `DeleteOwnResources` | `DeleteSnapshot` / `DeleteVolume`, only where `ec2:ResourceTag/scanner:managed` is `true` |
| `ResultsBucket` | `s3:PutObject` to the results bucket |
| `TaskLogs` | Writes to this stack's log group |
| `SecretsAccess` | `secretsmanager:GetSecretValue` on one secret ARN — whichever holds the token, created here or supplied by you |
| `ConsumeScanQueue` | Receive, delete and extend visibility on the scan queue |
| `ScanNotificationsToSNS` | `sns:Publish` to the configured topic, when one is set |
| `ScanNotificationsKMS` | `kms:GenerateDataKey` / `kms:Decrypt`, only for a customer-managed topic key |

**Some actions are split by resource type.** Several EC2 actions authorise
against more than one resource, and a tag condition applies to every one of
them: `ec2:CreateVolume` from a snapshot is checked against both the new volume
and the source snapshot. Only one resource in each pair carries the scanner's
tag, so a single statement with a tag condition would fail on the other leg and
deny the whole call. Splitting each action keeps the tag requirement where it
constrains something.

**Two read legs are unconditional.** `ec2:CopySnapshot` and the
`SnapshotSourceVolume` leg of `ec2:CreateSnapshot` do not support
`aws:RequestTag` — AWS authorises them against the source resource, which the
scanner neither owns nor can tag. Both are read-only, and the copy they produce
is tagged at creation.

**Deletion stays tag-scoped regardless.** `DeleteSnapshot` and `DeleteVolume`
are gated on `ec2:ResourceTag/scanner:managed`, which those APIs do support, so
the scanner cannot delete anything it did not create.

## ReversingLabs endpoint and token

`reversinglabs_api_url` is **required** — it becomes the daemon's
`REVERSINGLABS_API_URL`, the endpoint the scanner submits files to.

It may name a single Spectra Detect Worker, which analyses files, or a Hub,
which ingests them and distributes them to Workers. See the
[Spectra Detect deployment documentation](https://docs.reversinglabs.com/SpectraDetect/Deployment/)
for the architecture.

When it names a Hub, submissions come back with a task URL on a different
host, and polling that host sends it the API token. The scanner therefore
refuses any task host it was not told to trust, so a Hub deployment must list
the hosts it may poll in `reversinglabs_allowed_task_hosts`:

```hcl
reversinglabs_api_url            = "https://hub.example.com"
reversinglabs_allowed_task_hosts = [".workers.example.com"]
```

| Entry form | Matches |
|---|---|
| `worker01.example.com` | that host exactly |
| `.workers.example.com` | any host in that domain — a pool that scales needs no redeploy |
| `*` | any host the Hub names |

Matching is by hostname and ignores the port. Pointing `reversinglabs_api_url`
at a Worker directly leaves this empty — the default — and the scanner polls
only that host.

The token reaches the scanner through Secrets Manager, never as a variable in
state: set `reversinglabs_api_token` and terraform creates the secret, or set
`reversinglabs_api_token_secret_arn` to reuse one you own. Setting both, or
neither, fails at plan time.

## Scheduled scans

Off by default. `enable_scan_schedule` turns on periodic discovery:

1. An **EventBridge Scheduler** rule fires on `scan_schedule_expression`
   (`rate(1 day)` by default).
2. It launches a **throwaway EC2 instance** from the scanner AMI running
   `scanner dispatch`, which discovers tagged assets, sends one message per
   asset to the scan queue, and terminates.
3. The **daemon** on each scanner instance drains that queue, one asset at a
   time.

The daemon is a systemd unit written by the launch template's user_data.
`daemon_max_scans` (default `0`, unbounded) bounds one daemon *process*, not
the instance; `1` gives each asset a fresh process at the cost of a restart
between scans.

`enable_scan_schedule` and `enable_eventbridge_trigger` combine freely. Both
produce onto the same queue and both are drained by the same daemon.

**Set `scan_schedule_expression` longer than a full drain takes.** Discovery
does not know what is already queued, so a tick that fires while a backlog is
still draining enqueues those assets again. The daemon scans each message it
receives, so the effect is repeated work rather than a stuck queue. A daily
schedule is comfortable for hundreds of assets; shorten it only if a full pass
reliably completes well inside the interval.

## Event-driven scans

Off by default. `enable_eventbridge_trigger` creates a rule that enqueues a
scan message **whenever an AMI becomes available**:

```bash
terraform apply -var="enable_eventbridge_trigger=true"
```

Scanning stays opt-in per image: the scanner checks the tag when it picks the
message up, and an AMI without it is skipped.

```bash
aws ec2 create-tags --resources ami-xxxxxxxxxxxxxxxxx --tags Key=RLScan,Value=true
```

The tag is reserved and not configurable. The value is matched exactly and
case-sensitively: `RLScan=True` does not match.

**Tag before or during the build.** The rule fires on the readiness event,
which carries no tags, so the tag is read later — when the daemon picks the
message up. An AMI tagged after that point is not re-triggered; enqueue it
manually, or wait for the next scheduled discovery if that is enabled.

Every new AMI in the account produces one queue message, tagged or not.
Untagged ones are skipped in seconds, but a burst of AMI creations can briefly
grow the fleet: the backlog metric counts messages, not scannable assets.

## Monitoring

```bash
aws logs tail "$(terraform output -raw cloudwatch_log_group)" --follow
```

Filter one scan by its trace id:

```bash
aws logs filter-log-events \
  --log-group-name "$(terraform output -raw cloudwatch_log_group)" \
  --filter-pattern '"<trace-id>"'
```

The daemon logs a structured `asset scan finished` line carrying the outcome:
`complete`, `partial`, `skipped` or `failed`.

Two alarms ship with the stack. One fires when work is outstanding with no
throughput — a wedged or idle fleet. The other fires when in-service instances
are sending no logs at all, which the first cannot see: log shipping can fail
while scans still run and still write reports, so throughput looks healthy
while every scan is unobservable.

### Log level

The log level is a property of the deployment, not of one scan — the daemon is
long-lived and shared. Set `var.scan_log_level` (`debug`, `info`, `warn`,
`error`) and apply:

```bash
terraform apply -var scan_log_level=debug
```

Instances render their unit from user_data, so the new level takes effect on
instances launched after the apply.

### On the host

```bash
aws ssm start-session --target <instance-id>
```

## Results

Reports are written to the bucket named by `terraform output
s3_results_bucket`, under prefix `reports`:

```
s3://<bucket>/reports/<resource-id>/<YYYYMMDD>T<HHMMSS>Z.json
```

The report format, the SNS notification and the fields they share are
documented in the [repository README](../README.md#output-envelope).

## Deploy-time IAM

`deploy_role_trusted_principal_arns` creates a role for operators or CI to
assume when listing scannable assets. It grants `ec2:DescribeImages` and
nothing else — it has no part in a scan. Left empty, the role is not created.

## Cleanup

```bash
terraform destroy
```

Empty the results bucket first; S3 refuses to delete a bucket that still holds
objects. Snapshots and volumes the scanner created are deleted as each scan
ends, so a destroy after a completed scan leaves nothing behind.
