# AWS AMI Scanner - ECS Deployment (Terraform)
# Canonical, terraform-only ECS deploy path. See ../README.md for the
# deploy-method index.

terraform {
  # >= 1.9 for cross-variable validation: several variable validation blocks
  # reference another variable (the mutually exclusive token and SNS topic
  # sources), which earlier versions reject outright.
  required_version = ">= 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

locals {
  name_prefix = "ami-scanner-${var.environment}"

  # Named here rather than inline on the resources because the daemon's
  # drain script needs both by NAME, and cannot take a resource reference:
  # the script is baked into the launch template, which the ASG consumes, so
  # referencing aws_autoscaling_group.ecs_instances from it is a cycle.
  # A shared local is what keeps the literal in the script and the real
  # resource name from drifting apart -- a rename that touched only one would
  # break lifecycle completion silently, with nothing to catch it.
  #
  # Derived from name_prefix rather than spelled out again: three copies of the
  # same literal is exactly the drift this comment warns about.
  asg_name = "${local.name_prefix}-asg"

  # The AMI both the daemon and the ephemeral dispatch instance boot from.
  # One expression because there is one artifact: an empty var.scanner_ami_id
  # falls back to stock AL2023, which boots and registers but carries no
  # scanner binary, and both user_data scripts fail loudly on that rather
  # than idling.
  scanner_image_id     = var.scanner_ami_id != "" ? var.scanner_ami_id : data.aws_ssm_parameter.ecs_ami.value
  scan_drain_hook_name = "${local.name_prefix}-scan-drain"
  # Name, Environment, Service, Usage, Customer and Owner are mandatory under
  # the account's tag policy -- omitting any of them makes the API deny the
  # call with a bare AccessDenied/UnauthorizedOperation that names the action
  # rather than the missing tag, which reads like a missing IAM permission.
  # Resources that want a more specific Name override it via merge().
  # The tag set handed to the scanner for the snapshots and volumes it creates,
  # as the comma-separated Key=Value pairs SCANNER_AWS_RESOURCE_TAGS takes.
  # Defined once because it is consumed twice -- by the daemon unit and by the
  # ECS task definition -- and the two must not drift.
  #
  # This is the RAW form. The daemon unit must escape "%" before using it (see
  # its templatefile call); an ECS env var must not, since it is not systemd.
  # Copying one site's expression to the other is therefore a bug in either
  # direction, which is why the escaping lives at the systemd site rather than
  # here.
  scanner_resource_tags = join(",", [for k, v in local.common_tags : "${k}=${v}"])

  # Scanner file filters, as systemd Environment= lines.
  #
  # The numeric caps are emitted unconditionally, the lists only when non-empty.
  # An earlier version suppressed a number equal to the scanner's own default,
  # which silently coupled these expressions to a default defined in the scanner
  # rather than here: changing it there would have changed what a deployment
  # sent, with nothing asserting the two agreed. The variable defaults in this
  # file are now the deployed values, and the unit states every cap in force.
  scanner_filter_env = {
    SCANNER_SCAN_MODE          = var.scan_mode
    SCANNER_EXCLUDE_CATEGORIES = join(",", var.scan_exclude_categories)
    SCANNER_INCLUDE_CATEGORIES = join(",", var.scan_include_categories)
    SCANNER_EXCLUDE_MIME       = join(",", var.scan_exclude_mime)
    SCANNER_INCLUDE_MIME       = join(",", var.scan_include_mime)
    SCANNER_EXCLUDE_PATHS      = join(",", var.scan_exclude_paths)
    SCANNER_INCLUDE_PATHS      = join(",", var.scan_include_paths)
    SCANNER_FILE_EXTENSIONS    = join(",", var.scan_file_extensions)
    SCANNER_MAX_FILES          = tostring(var.scan_max_files)
    SCANNER_MAX_FILE_SIZE      = tostring(var.scan_max_file_size)
    SCANNER_MIN_FILE_SIZE      = tostring(var.scan_min_file_size)
  }

  # Quoted and "%"-doubled for the same reasons the tag set is, and it matters
  # identically here: see the escaping comment at its templatefile call.
  scanner_filter_env_lines = join("\n", [
    for k, v in local.scanner_filter_env : "Environment=\"${k}=${replace(v, "%", "%%")}\""
    if v != ""
  ])

  # var.resource_tags is merged UNDER the stack's own keys deliberately: Project
  # gates the task role's AttachVolume/DetachVolume grant and ManagedBy
  # distinguishes a terraform-created resource from a scanner-created one, so
  # neither may be redefined by configuration.
  common_tags = merge(var.resource_tags, {
    Name      = local.name_prefix
    Project   = var.tag_project
    Method    = "ec2"
    ManagedBy = "terraform"
  })

  # The topic comes either from one this stack creates or from one the
  # operator already owns; variable validation guarantees at most one. Empty
  # when neither, which is what disables the scanner's SNS output action --
  # every SNS grant, env var and output below keys off this single value, so
  # there is one place that decides which topic is in play.
  sns_topic_arn = var.create_sns_topic ? aws_sns_topic.alerts[0].arn : var.sns_alert_topic_arn

  # A customer-managed key needs explicit kms grants on the task role;
  # alias/aws/sns does not, and cannot be granted on anyway (AWS-managed key
  # policies are not editable and the grant is implicit for the service).
  #
  # Keyed on the value being a key ARN rather than on it not being the literal
  # "alias/aws/sns": variable validation admits only those two shapes, so "is
  # an ARN" identifies a customer-managed key exactly, and any unexpected
  # third form fails validation instead of silently landing in this branch and
  # producing a KMS grant against something that cannot be granted on.
  sns_topic_customer_managed_key = var.create_sns_topic && can(regex("^arn:aws:kms:", var.sns_topic_kms_master_key_id))

  # The token comes either from a secret this stack creates or from one the
  # operator already owns; variable validation guarantees exactly one.
  # nonsensitive(): branching on the sensitive token variable would otherwise
  # mark the ARN sensitive too. An ARN is an identifier, not a credential --
  # it is printed in outputs and the README tells operators to read it.
  reversinglabs_api_token_secret_arn = nonsensitive(
    var.reversinglabs_api_token != ""
    ? aws_secretsmanager_secret.reversinglabs_api_token[0].arn
    : var.reversinglabs_api_token_secret_arn
  )
}

module "network" {
  source     = "../modules/network"
  vpc_id     = var.vpc_id
  subnet_ids = var.subnet_ids
}

# Security Group
resource "aws_security_group" "scanner" {
  name        = "${local.name_prefix}-sg"
  description = "Security group for AMI Scanner ECS tasks"
  vpc_id      = module.network.vpc_id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for ReversingLabs API"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-sg"
  })
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/ec2/${local.name_prefix}"
  retention_in_days = 30

  tags = local.common_tags
}

# IAM Role for ECS Task (runtime)
# The scan permissions live here and are reached two ways, because a scan runs
# two ways. An ECS task gets them from the task role directly, the way ECS
# always supplied them. The scanner daemon runs under systemd as a plain
# `docker run`, has no task role, and would otherwise fall back to whatever
# the INSTANCE profile grants -- so instead the instance assumes this role
# (see aws_iam_role_policy.ecs_instance_assume_scan_role).
#
# Assumption rather than copying these statements onto the instance role: the
# host runs a privileged container over untrusted filesystems, and anything
# on it can read IMDS. Keeping the instance's own credentials near-powerless
# means a host compromise does not directly confer snapshot, attach, delete
# and secret-read -- it has to assume this role first, which is a distinct
# CloudTrail event that can be alarmed on. Defence in depth and an audit
# trail, not a hard boundary: a process on the host can assume it too.
resource "aws_iam_role" "ecs_task" {
  name = "${local.name_prefix}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECSTasksAssume"
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
      {
        Sid    = "ScannerInstanceAssume"
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ecs_instance.arn
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "ecs_task_scanner" {
  name = "${local.name_prefix}-scanner-policy"
  role = aws_iam_role.ecs_task.id

  # Statements mirror the reviewed least-privilege policy (the
  # design) plus the scanner-runtime-only additions CopySnapshot, preflight
  # STS/IAM checks, S3 results, secrets access, and task logs.
  policy = jsonencode({
    Version = "2012-10-17"
    # The SNS statement is appended only when a topic is in play (managed or
    # supplied) -- an empty Resource would make the statement (and the apply)
    # invalid.
    Statement = concat([
      {
        # Read-only discovery: no scoping possible, these act on caller-supplied
        # AMI/region/instance IDs before the scanner has created anything.
        Sid    = "DiscoverAssets"
        Effect = "Allow"
        Action = [
          "ec2:DescribeImages",
          "ec2:DescribeVolumes",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeSnapshots",
          "ec2:DescribeTags",
          "ec2:DescribeRegions"
        ]
        Resource = "*"
      },
      {
        # The snapshot being created. It carries the request tag, so the
        # condition resolves and scopes this to scanner-owned snapshots.
        #
        # Account segment is a wildcard, not empty. The empty form
        # (arn:aws:ec2:*::snapshot/*) is the shape a SOURCE snapshot takes
        # when it is public or shared; a snapshot the scanner creates is
        # always owned by this account. Both have been matching in practice,
        # so this states the intent rather than fixing a live denial.
        Sid      = "CreateTaggedSnapshot"
        Effect   = "Allow"
        Action   = "ec2:CreateSnapshot"
        Resource = "arn:aws:ec2:*:*:snapshot/*"
        Condition = {
          StringEquals = {
            "aws:RequestTag/scanner:managed" = "true"
          }
        }
      },
      {
        # The SOURCE VOLUME of that same call. ec2:CreateSnapshot authorises
        # against two resources -- the snapshot being created and the volume
        # being read -- and a single Resource="*" statement carrying an
        # aws:RequestTag condition satisfies only the first. Request tags
        # describe the resource being created, so on the volume leg the
        # condition never resolves, the statement does not match, and the
        # whole call is denied with "no identity-based policy allows the
        # ec2:CreateSnapshot action" even though the scanner does send
        # scanner:managed=true. Same shape as the CopySnapshot case below.
        #
        # Deliberately NOT scoped by the scan tag. That tag is the
        # application's opt-in gate over the asset an operator named
        # (the scanner's tag gate), and it is reserved rather than
        # configurable, so IAM could in principle encode it. It still should
        # not: a skip is a first-class outcome the scanner reports as exit 4
        # with the reason named, whereas an IAM denial surfaces as a bare
        # AccessDenied naming ec2:CreateSnapshot. That reads as a missing
        # permission rather than a policy decision, which is the exact
        # confusion this repo's tagging notes warn about. Authorisation and
        # the scan gate are separate concerns and belong in separate layers.
        #
        # Left open for the same reason CopySnapshot below is: reading a
        # volume in order to snapshot it is non-destructive, the snapshot it
        # produces is still tag-scoped by the statement above, and every
        # destructive action stays scoped by ec2:ResourceTag -- so the
        # scanner still cannot delete anything it did not create.
        Sid      = "SnapshotSourceVolume"
        Effect   = "Allow"
        Action   = "ec2:CreateSnapshot"
        Resource = "arn:aws:ec2:*:*:volume/*"
      },
      {
        # Unconditional, unlike CreateSnapshot above: ec2:CopySnapshot does
        # not support aws:RequestTag as a condition key. AWS authorises it
        # against the *source* snapshot, which the scanner does not own and
        # cannot tag -- for an Amazon-published AMI the source ARN does not
        # even carry an account ID. A RequestTag condition therefore never
        # resolves, the statement never matches, and the call is denied with
        # "no identity-based policy allows the ec2:CopySnapshot action" even
        # though the scanner does send scanner:managed=true (snapshot.go).
        #
        # This lets the task copy any snapshot it can read. That is inherent
        # to the API and unavoidable for scanning AMIs the account does not
        # own. Copying is read-only, TagOnCreate below still tags the copy,
        # and the destructive actions stay tag-scoped via ec2:ResourceTag --
        # which those APIs do support -- so the scanner still cannot delete
        # anything it did not create.
        Sid      = "CopySourceSnapshot"
        Effect   = "Allow"
        Action   = "ec2:CopySnapshot"
        Resource = "*"
      },
      {
        Sid      = "TagOnCreate"
        Effect   = "Allow"
        Action   = "ec2:CreateTags"
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = ["CreateSnapshot", "CopySnapshot"]
          }
        }
      },
      {
        # Scoped to volume/* on purpose. ec2:CreateVolume from a snapshot
        # authorises against two resources: the volume being created, which
        # carries the request tag, and the source snapshot, which does not --
        # you are not creating the snapshot, so aws:RequestTag never resolves
        # for it. With Resource = "*" the condition was applied to the
        # snapshot leg too, the statement failed to match, and the call was
        # denied on "arn:aws:ec2:us-east-1::snapshot/snap-..." despite the
        # scanner sending the tag (volume.go). Splitting by resource type
        # keeps the tag requirement exactly where it is meaningful.
        Sid      = "CreateTaggedVolume"
        Effect   = "Allow"
        Action   = "ec2:CreateVolume"
        Resource = "arn:aws:ec2:*:*:volume/*"
        Condition = {
          StringEquals = {
            "aws:RequestTag/scanner:managed" = "true"
          }
        }
      },
      {
        # The source-snapshot leg of the same CreateVolume call. Read-only in
        # effect: it permits reading a snapshot to populate a new volume, and
        # cannot create anything on its own. The volume leg above still
        # refuses to create an untagged volume, so cleanup guarantees hold.
        #
        # Wildcard account segment rather than the empty one. Source
        # snapshots come in both shapes: a public or shared snapshot behind
        # someone else's AMI carries no account, while the scratch snapshot
        # the volume path creates is owned by this one. The empty form has
        # been matching both in practice, so this is a clarity change and not
        # a fix -- but it states the intent instead of relying on how EC2
        # happens to normalise a missing segment.
        Sid      = "CreateVolumeFromSnapshot"
        Effect   = "Allow"
        Action   = "ec2:CreateVolume"
        Resource = "arn:aws:ec2:*:*:snapshot/*"
      },
      {
        Sid      = "TagVolumeOnCreate"
        Effect   = "Allow"
        Action   = "ec2:CreateTags"
        Resource = "arn:aws:ec2:*:*:volume/*"
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = "CreateVolume"
          }
        }
      },
      {
        # Volume leg of Attach/Detach: still restricted to volumes this
        # scanner created and tagged.
        Sid    = "AttachDetachOwnVolumes"
        Effect = "Allow"
        Action = [
          "ec2:AttachVolume",
          "ec2:DetachVolume"
        ]
        Resource = "arn:aws:ec2:*:*:volume/*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/scanner:managed" = "true"
          }
        }
      },
      {
        # Instance leg of the same calls. Attach/Detach authorise against the
        # instance as well as the volume, and the container instance is not
        # tagged scanner:managed -- it is created by the launch template, not
        # by the scanner -- so requiring that tag here denies every attach.
        #
        # Scoped instead to instances belonging to this stack, which is the
        # tightest condition available: the scanner only ever attaches to the
        # host it is running on. Combined with the volume leg above, the task
        # can attach only its own volumes, and only to its own instances.
        Sid    = "AttachDetachOnScannerInstances"
        Effect = "Allow"
        Action = [
          "ec2:AttachVolume",
          "ec2:DetachVolume"
        ]
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Project" = var.tag_project
          }
        }
      },
      {
        Sid    = "DeleteOwnResources"
        Effect = "Allow"
        Action = [
          "ec2:DeleteSnapshot",
          "ec2:DeleteVolume"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/scanner:managed" = "true"
          }
        }
      },
      {
        Sid    = "PreflightPermissionCheck"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity",
          "iam:SimulatePrincipalPolicy"
        ]
        Resource = "*"
      },
      {
        Sid      = "ResultsBucket"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.results.arn}/*"
      },
      {
        Sid    = "TaskLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.scanner.arn}:*"
      }
      ],
      [
        # The task needs to read the RL API
        # token secret. Unconditional -- variable validation guarantees a
        # token source, so this ARN is never empty.
        {
          Sid      = "SecretsAccess"
          Effect   = "Allow"
          Action   = "secretsmanager:GetSecretValue"
          Resource = local.reversinglabs_api_token_secret_arn
        },
        # Draining the scan queue. On THIS role rather than the instance role
        # because the daemon assumes this role at startup and then does
        # everything through it -- a grant on the instance profile is not in
        # effect by the time it polls, which is exactly how this was first
        # written and why every receive came back AccessDenied.
        #
        # Deliberately NOT sqs:SendMessage: a worker draining the queue has no
        # reason to write to it, and a compromised scan of an untrusted disk
        # image must not be able to enqueue arbitrary work. Producing is the
        # dispatcher's privilege (aws_iam_role_policy.dispatcher).
        #
        # ChangeMessageVisibility is not optional: the daemon heartbeats the
        # in-flight message to hold its lease for the length of a scan, and
        # without it the message redelivers mid-scan and a second worker picks
        # up the same asset.
        {
          Sid    = "ConsumeScanQueue"
          Effect = "Allow"
          Action = [
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:ChangeMessageVisibility",
            "sqs:GetQueueAttributes"
          ]
          Resource = aws_sqs_queue.scan.arn
        }
      ],
      # SNS output action (config: output.sns.enabled). The S3 output action
      # needs no extra grant -- it reuses the ResultsBucket statement above.
      local.sns_topic_arn == "" ? [] : [
        {
          Sid      = "ScanNotificationsToSNS"
          Effect   = "Allow"
          Action   = "sns:Publish"
          Resource = local.sns_topic_arn
        }
      ],
      # Publishing to a topic encrypted with a customer-managed key needs
      # kms:GenerateDataKey on that key as well as sns:Publish. Without it
      # Publish fails at runtime with a KMS AccessDenied -- after a scan has
      # already run, and nowhere near plan time. kms:Decrypt is what lets a
      # subscriber-side redrive re-read the message.
      local.sns_topic_customer_managed_key ? [
        {
          Sid    = "ScanNotificationsKMS"
          Effect = "Allow"
          Action = [
            "kms:GenerateDataKey",
            "kms:Decrypt",
          ]
          Resource = var.sns_topic_kms_master_key_id
        }
      ] : []
    )
  })
}

# IAM Role for deploy-time operations (the scanner `list` subcommand)
#
# Trust boundary: assumable by an operator principal (human IAM user/role or CI
# pipeline role), NOT by the ecs_task role. The role no longer carries any
# grant that could launch a scan -- ecs:RunTask and iam:PassRole went with
# `scanner deploy` -- but the separation is kept: it is an operator role, and
# a running scan container has no business assuming one.
#
# var.deploy_role_trusted_principal_arns must list the exact ARNs allowed to
# assume this role (operator IAM role/user ARNs, or a CI role ARN).
#
# The role is created only when that list is non-empty. IAM rejects a trust
# policy whose principal list is empty ("statement with no principals"), so
# defaulting to an empty list previously failed the whole apply rather than
# producing an unusable role. Nothing else depends on this role, so skipping
# it costs only the `scanner list` subcommand.
resource "aws_iam_role" "scanner_deploy" {
  count = length(var.deploy_role_trusted_principal_arns) > 0 ? 1 : 0
  name  = "${local.name_prefix}-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { AWS = var.deploy_role_trusted_principal_arns }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "scanner_deploy" {
  count = length(var.deploy_role_trusted_principal_arns) > 0 ? 1 : 0
  name  = "${local.name_prefix}-deploy-policy"
  role  = aws_iam_role.scanner_deploy[0].id

  # Read-only, and deliberately so. This role used to carry
  # ecs:RegisterTaskDefinition/RunTask/DescribeTasks plus iam:PassRole on both
  # task roles, because `scanner deploy` launched a scan by running an ECS
  # task. Nothing launches a scan that way any more: a scan is requested by
  # putting a message on the scan queue, so the ability to run a task and to
  # pass a role are no longer needed by any operator workflow and are not
  # granted.
  #
  # What remains is what `scanner list` reads. Note this role does NOT grant
  # sqs:SendMessage -- asking for a scan is a separate privilege from
  # enumerating what could be scanned, and it is granted where the queue is
  # defined.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListScannableAMIs"
        Effect   = "Allow"
        Action   = "ec2:DescribeImages"
        Resource = "*"
      }
    ]
  })
}

# --- EC2 capacity -----------------------------------------------------------
# The scanner mounts EBS snapshots as block devices, which Fargate cannot do
# (no privileged containers, no host device access). Tasks therefore run on
# EC2 container instances managed by the ASG below.

resource "aws_iam_role" "ecs_instance" {
  name = "${local.name_prefix}-ecs-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })

  tags = local.common_tags
}

# SSM Session Manager access for debugging a running scan host without SSH.
resource "aws_iam_role_policy_attachment" "ecs_instance_ssm" {
  role       = aws_iam_role.ecs_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# The instance's own grants. Deliberately minimal: the right to become the
# scan role, and the right to ship the daemon's logs. Everything a scan
# actually does is on aws_iam_role.ecs_task, reached by assumption, so a host
# compromise does not directly confer snapshot/attach/delete/secret-read.
resource "aws_iam_role_policy" "ecs_instance_assume_scan_role" {
  name = "${local.name_prefix}-instance-assume-scan-role"
  role = aws_iam_role.ecs_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssumeScanRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.ecs_task.arn
      },
      # The CloudWatch agent tails /var/log/scanner-daemon.log and ships it,
      # running under the INSTANCE profile -- not the assumed scan role, which
      # only the daemon process itself uses. The container's awslogs driver
      # used to do this under the ECS agent's own grants; with the container
      # gone, the instance needs the write itself.
      {
        Sid    = "ShipDaemonLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
        ]
        Resource = "${aws_cloudwatch_log_group.scanner.arn}:*"
      },
      # DescribeLogGroups is called at agent startup and takes NO resource
      # qualifier -- it is a list operation over the account, so an ARN-scoped
      # Resource never matches and the call comes back AccessDenied. That
      # failure is silent by construction: user_data's fetch-config is
      # best-effort, so the instance boots healthy and ships nothing.
      #
      # Deliberately the only "*" here, and read-only: it reveals log group
      # names in the account and grants nothing on their contents. The write
      # actions above stay pinned to this stack's group.
      {
        Sid      = "DiscoverLogGroups"
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ecs_instance" {
  name = "${local.name_prefix}-ecs-instance-profile"
  role = aws_iam_role.ecs_instance.name

  tags = local.common_tags
}

# The kernel version is load-bearing, so the base cannot be chosen casually:
# scan volumes come from modern RHEL-family AMIs whose root xfs sets
# INOBTCNT and BIGTIME superblock features, which first appear in kernel 5.10.
# An older kernel rejects the mount outright with "Filesystem cannot be safely
# mounted by this kernel". Containers share the host kernel, so only the
# instance AMI fixes this. AL2023 is 6.1 and knows both.
#
# Moving here also brings cgroup v2 and util-linux 2.37.4, which emits
# `lsblk -J -b` sizes as bare JSON numbers where Rocky 8's 2.32.1 quotes
# them. The scanner accepts both spellings -- without that, this base
# change alone would send every scan down the blind fallback.
#
# FALLBACK ONLY: boots and registers with the cluster but carries no scanner
# binary, so the daemon cannot start. var.scanner_ami_id is the real input.
data "aws_ssm_parameter" "ecs_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
}

resource "aws_launch_template" "ecs_instance" {
  name_prefix = "${local.name_prefix}-"
  # Falls back to the stock AL2023 AMI so the stack applies before the first
  # Packer build exists. That fallback does not scan -- see the variable.
  image_id      = local.scanner_image_id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.ecs_instance.arn
  }

  vpc_security_group_ids = [aws_security_group.scanner.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  # user_data and the systemd unit live in templates/ rather than in a heredoc
  # here. Two reasons, both learned the hard way: a heredoc-in-heredoc depends
  # on invisible indentation to render a valid unit file, and line
  # continuations inside one get eaten, which silently collapsed the docker
  # command into one unreviewable 900-character line. Real files render
  # exactly as written and can be linted (bash -n, systemd-analyze verify).
  user_data = base64encode(templatefile("${path.module}/templates/user-data.sh.tftpl", {
    aws_region = var.aws_region
    # No `image` and no `rl_token_secret_arn` here any more: user_data performs
    # no ECR login and no pull, and the secret ARN reaches the daemon through
    # the unit's Environment= rather than anything written at boot.
    #
    # log_group is new: the CloudWatch agent config is written at boot because
    # the group name is only known at apply time, and it replaces the log
    # shipping the container's awslogs driver used to do.
    log_group           = aws_cloudwatch_log_group.scanner.name
    asg_name            = local.asg_name
    lifecycle_hook_name = local.scan_drain_hook_name

    daemon_unit = templatefile("${path.module}/templates/scanner-daemon.service.tftpl", {
      aws_region     = var.aws_region
      scan_role_arn  = aws_iam_role.ecs_task.arn
      scan_queue_url = aws_sqs_queue.scan.url
      log_level      = var.scan_log_level
      results_bucket = aws_s3_bucket.results.id

      # Tags for the snapshots and volumes a scan creates. The same
      # local.common_tags the terraform resources carry, so one set describes
      # the whole deployment. The scanner applies its own tags on top and
      # they cannot be overridden from here, so the ManagedBy=terraform in
      # common_tags loses to ManagedBy=ami-scanner on a scanner-created
      # resource -- deliberately, since cleanup and the CreateSnapshot IAM
      # condition both key off the scanner's own tags.
      # "%" is doubled because systemd expands specifiers (%H, %i, ...) in
      # Environment= as well as ExecStart: an unescaped "%H" becomes the
      # hostname, and an invalid one such as the "%o" in "50%off" makes the
      # unit refuse to load at all, leaving the instance with no daemon while
      # the queue backs up silently. "%%" is systemd's literal-percent escape.
      # Still required after the container removal -- the values moved from
      # `docker run -e` to Environment=, which expands specifiers identically.
      resource_tags         = replace(local.scanner_resource_tags, "%", "%%")
      reversinglabs_api_url = var.reversinglabs_api_url
      max_scans             = var.daemon_max_scans
      rl_token_secret_arn   = local.reversinglabs_api_token_secret_arn
      idle_timeout          = var.daemon_idle_timeout

      # Empty unless a filter variable was set, so the default deployment's
      # unit is unchanged by this block existing.
      filter_env = local.scanner_filter_env_lines

      # Empty when no topic is configured, which disables the SNS output
      # action exactly as it does for the ECS task -- every SNS grant, env
      # var and output in this stack keys off local.sns_topic_arn, so there
      # is one place that decides whether notifications happen at all.
      # systemd `Environment=` syntax, not `docker run -e`: the daemon is a
      # host process now, so the whole fragment is a unit directive rather
      # than a command-line argument.
      sns_topic_env = local.sns_topic_arn == "" ? "" : "Environment=SCANNER_OUTPUT_SNS_TOPIC_ARN=${local.sns_topic_arn}"

      # Worker hosts the scanner may poll for task results beyond the api_url
      # host itself. Only meaningful for a Hub deployment, which hands back
      # task URLs on other hosts; empty for a Worker-direct one, which is why
      # the fragment disappears entirely rather than setting an empty value.
      allowed_task_hosts_env = length(var.reversinglabs_allowed_task_hosts) == 0 ? "" : "Environment=REVERSINGLABS_ALLOWED_TASK_HOSTS=${join(",", var.reversinglabs_allowed_task_hosts)}"
    })
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-ecs-instance"
    })
  }

  # The root volume is a separate taggable resource created by the same
  # RunInstances call, so the tag policy applies to it independently of the
  # instance -- without this the launch is denied.
  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-ecs-instance-root"
    })
  }

  tags = local.common_tags
}

resource "aws_autoscaling_group" "ecs_instances" {
  name                = local.asg_name
  min_size            = var.asg_min_size
  max_size            = var.asg_max_size
  desired_capacity    = var.asg_desired_capacity
  vpc_zone_identifier = module.network.subnet_ids

  launch_template {
    id      = aws_launch_template.ecs_instance.id
    version = "$Latest"
  }

  # ASG group metrics are OPT-IN: without this, GroupInServiceInstances
  # publishes no datapoints at all and the log-silence alarm below -- which
  # keys off "in-service instances exist" -- can never evaluate its own
  # precondition. Only the two the alarm reads are enabled.
  metrics_granularity = "1Minute"
  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
  ]

  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

# Secrets Manager secret holding the ReversingLabs Spectra Detect API token.
# Created only when var.reversinglabs_api_token is set; otherwise the operator
# supplied var.reversinglabs_api_token_secret_arn and owns the secret already.
# The value never gets written to disk or committed -- pass it via -var or
# TF_VAR_reversinglabs_api_token at apply time.
#
# name_prefix, not name: a deleted secret keeps its name reserved for the
# whole recovery window (30 days by default), so a fixed name makes any
# destroy/apply cycle fail with InvalidRequestException until the window
# expires. The prefix lets AWS append a unique suffix each time. Consumers
# resolve the secret through the terraform output or the task definition,
# never by typing its name, so the suffix costs nothing.
resource "aws_secretsmanager_secret" "reversinglabs_api_token" {
  count       = var.reversinglabs_api_token != "" ? 1 : 0
  name_prefix = "${local.name_prefix}-rl-api-token-"

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "reversinglabs_api_token" {
  count         = var.reversinglabs_api_token != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.reversinglabs_api_token[0].id
  secret_string = var.reversinglabs_api_token
}

# S3 Bucket for scan results
resource "aws_s3_bucket" "results" {
  bucket = "${local.name_prefix}-results-${data.aws_caller_identity.current.account_id}"

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "results" {
  bucket = aws_s3_bucket.results.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  # SSE-S3 (not SSE-KMS): KMS was never a stated requirement (no compliance
  # doc calls for it) and the task role had no KMS permissions, so the
  # first real scan's upload would fail AccessDenied.
  # SSE-S3 needs no separate key/permissions -- s3:PutObject/GetObject alone
  # is sufficient.
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Asserted here rather than inherited from the account-level Block Public
# Access default, which this stack cannot see. Reports name malware paths
# inside customer AMIs.
resource "aws_s3_bucket_public_access_block" "results" {
  bucket = aws_s3_bucket.results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE covers the reports at rest; this covers them in transit. The Deny binds
# every principal including the scanner's own task role, which is harmless:
# the AWS SDK talks HTTPS by default.
data "aws_iam_policy_document" "results_tls_only" {
  statement {
    sid    = "DenyNonTLSAccess"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.results.arn,
      "${aws_s3_bucket.results.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "results" {
  bucket = aws_s3_bucket.results.id
  policy = data.aws_iam_policy_document.results_tls_only.json

  # Ordered after the public-access-block, so BlockPublicPolicy is already
  # enforcing when the policy lands.
  depends_on = [aws_s3_bucket_public_access_block.results]
}

# Access logs for the results bucket. A separate bucket because S3 refuses a
# logging configuration that would feed a bucket its own access logs.
resource "aws_s3_bucket" "results_logs" {
  bucket = "${local.name_prefix}-results-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-results-logs" })
}

# Declared rather than left to the post-April-2023 default, because the
# log-delivery grant in the bucket policy below depends on it.
resource "aws_s3_bucket_ownership_controls" "results_logs" {
  bucket = aws_s3_bucket.results_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "results_logs" {
  bucket = aws_s3_bucket.results_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results_logs" {
  bucket = aws_s3_bucket.results_logs.id

  # SSE-S3, not KMS: log delivery cannot write to an SSE-KMS bucket without a
  # key policy granting the logging service.
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# No versioning, unlike the results bucket: log delivery only ever writes new
# objects, and versioning would retain delete markers past this expiry.
resource "aws_s3_bucket_lifecycle_configuration" "results_logs" {
  bucket = aws_s3_bucket.results_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

# Grants the log delivery service write access. Under BucketOwnerEnforced the
# legacy ACL grant no longer works, so it has to come from the bucket policy.
data "aws_iam_policy_document" "results_logs" {
  statement {
    sid    = "AllowS3ServerAccessLogging"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.results_logs.arn}/*"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.results.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "DenyNonTLSAccess"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.results_logs.arn,
      "${aws_s3_bucket.results_logs.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "results_logs" {
  bucket = aws_s3_bucket.results_logs.id
  policy = data.aws_iam_policy_document.results_logs.json

  depends_on = [aws_s3_bucket_public_access_block.results_logs]
}

resource "aws_s3_bucket_logging" "results" {
  bucket = aws_s3_bucket.results.id

  target_bucket = aws_s3_bucket.results_logs.id
  target_prefix = "results-access-logs/"

  # S3 validates write access to the target bucket at create time.
  depends_on = [aws_s3_bucket_policy.results_logs]
}

# --- EventBridge scan trigger ------------------------------------------------
# Opt-in (var.enable_eventbridge_trigger, default false): starts a scan task
# whenever an AMI in this account becomes available. Left off by default so
# applying the stack doesn't silently begin scanning.
#
# Scanning is still opt-in per image, but the filter is applied by the scanner
# rather than by this rule -- see the scan-gate comment below for why it
# cannot live here.

resource "aws_cloudwatch_event_rule" "ami_available" {
  count       = var.enable_eventbridge_trigger ? 1 : 0
  name        = "${local.name_prefix}-ami-available"
  description = "Start a scan task when an AMI becomes available (the scanner then gates on RLScan=true)"

  # Fire on readiness, not on tagging. An AMI is scannable only once it
  # reaches "available" -- its root snapshot does not exist before that -- so
  # this is the event that says "there is something here to scan".
  #
  # The tag filter is deliberately NOT here, because it cannot be: an
  # "EC2 AMI State Change" event carries only ImageId and State. It has no
  # Tags field, so there is nothing for an event pattern to match on. The
  # alternative -- triggering on "Tag Change on Resource", which does carry
  # tags -- was rejected: it requires an administrator to tag at exactly the
  # right moment, and it silently misses any AMI that was already tagged
  # before it finished building, which is the normal case for an image
  # pipeline that tags at registration time. Expecting customers to track
  # when an AMI becomes ready is not workable.
  #
  # So every new AMI starts a task, and the scanner checks the tag before
  # doing any real work (the scanner's tag gate). The
  # cost of that choice is one container start per untagged AMI, which exits
  # in seconds with exit code 4; the benefit is that an AMI is scanned
  # whenever it becomes ready, however it was tagged.
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 AMI State Change"]
    detail = {
      State = ["available"]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "scan_task" {
  count     = var.enable_eventbridge_trigger ? 1 : 0
  rule      = aws_cloudwatch_event_rule.ami_available[0].name
  target_id = "${local.name_prefix}-scan"
  arn       = aws_sqs_queue.scan.arn

  # No role_arn: an SQS target is authorised by the queue's resource policy
  # (aws_sqs_queue_policy.scan_eventbridge below), not by a role EventBridge
  # assumes. There is nothing to pass and nothing to run, so the RunTask role
  # this target used to need is gone entirely.

  # No dead_letter_config and no retry_policy. Delivery here is a single
  # SendMessage to a queue in the same account -- there is no capacity to
  # wait for and no task definition to get wrong, so the failure modes the
  # old RunTask retries covered do not exist on this path. A queue that
  # cannot accept the message is broken in a way a DLQ would not fix.

  # Builds a scan message, not a container override: the target is now the
  # queue the daemon drains, so this event enters the system by exactly the
  # same path as a scheduled `scanner dispatch` message. One format, one
  # consumer, one set of validation rules.
  #
  # No region field, deliberately -- a scan message carries (type, id,
  # trace_id) and the daemon scans in its own region. The old RunTask target
  # passed --region from $.region; cross-region AMI events are out of scope
  # for the daemon, which runs one region per deployment.
  input_transformer {
    input_paths = {
      ami_id   = "$.detail.ImageId"
      event_id = "$.id"
    }

    # trace_id comes straight from the event id with no Lambda in between: an
    # EventBridge event id is already a canonical lowercase dashed UUID,
    # which is exactly what the scanner's trace-id validation accepts.
    # Using it rather than minting a new one also ties every log line for this
    # scan back to the event that caused it.
    input_template = <<-EOT
      {
        "type": "ami",
        "id": <ami_id>,
        "trace_id": <event_id>
      }
    EOT
  }
}

# Lets the rule -- and only the rule -- put scan messages on the queue.
# Scoped by aws:SourceArn so a leaked queue URL cannot be used to inject work
# items through the EventBridge service principal.
#
# An aws_sqs_queue_policy sets the queue's ENTIRE policy document, so this is
# the queue's only one by construction. A second producer needing a resource
# policy here must add a statement to this list rather than declaring its own
# resource -- two of them do not conflict at plan time, they silently
# overwrite each other, and whichever applies last wins.
resource "aws_sqs_queue_policy" "scan_eventbridge" {
  count     = var.enable_eventbridge_trigger ? 1 : 0
  queue_url = aws_sqs_queue.scan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgeEnqueue"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.scan.arn
        Condition = {
          ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.ami_available[0].arn }
        }
      }
    ]
  })
}

# SNS topic for detection notifications
#
# Created only when var.create_sns_topic is set; an operator pointing at their
# own topic via var.sns_alert_topic_arn gets none of these resources. Before
# this existed the stack could grant sns:Publish and inject a topic ARN but
# never provision a topic, so a fresh deploy had no working SNS output and no
# documented way to get one.
resource "aws_sns_topic" "alerts" {
  count = var.create_sns_topic ? 1 : 0
  name  = "${local.name_prefix}-alerts"

  # Encrypted by default. A detection notification names malicious paths
  # inside a customer AMI, and the message body is the finding -- an
  # unencrypted topic is the wrong default for it.
  kms_master_key_id = var.sns_topic_kms_master_key_id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alerts"
  })
}

# Topic policy: only this account's principals may publish. Without an
# explicit policy the topic falls back to the owning account's implicit
# access, which is equivalent but says nothing -- and a subscription added
# later by hand is easier to reason about against a policy that states the
# boundary.
resource "aws_sns_topic_policy" "alerts" {
  count = var.create_sns_topic ? 1 : 0
  arn   = aws_sns_topic.alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOwnAccountPublish"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts[0].arn
        # Principal "*" scoped by SourceOwner: any principal in this account
        # that separately holds sns:Publish in its own IAM policy (the scanner
        # task role does), and nothing outside it.
        Condition = {
          StringEquals = { "AWS:SourceOwner" = data.aws_caller_identity.current.account_id }
        }
      }
    ]
  })
}

# Optional subscription, so a deploy can wire a recipient without a second
# manual step. An email subscription is pending until the recipient clicks
# confirm; terraform cannot see that, and reports the subscription as created
# either way -- so a silent notification pipeline is usually an unconfirmed
# subscription rather than a broken scanner.
resource "aws_sns_topic_subscription" "alerts" {
  count     = var.create_sns_topic && var.sns_subscription_protocol != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = var.sns_subscription_protocol
  endpoint  = var.sns_subscription_endpoint
}

# Data sources
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

# --- Scan queue -------------------------------------------------------------
# The work queue the daemon drains. One message is one asset.

# No DLQ, deliberately. A scan message is {type, id, trace_id} -- a DERIVED
# work item, re-derivable at any time by running discovery again. Losing one
# costs nothing: the next scheduled dispatch rediscovers the asset, still
# tagged and still unscanned. A DLQ with no consumer is a place failures go
# to be forgotten while appearing handled.
#
# This queue now also receives AMI-available events from the EventBridge rule,
# which ARE one-time facts rather than re-derivable work. Losing one costs a
# scan-on-readiness for that image -- but not the scan itself: the next
# scheduled dispatch still finds the AMI, tagged and unscanned, so the floor
# is a delayed scan rather than a missed one.
#
# The accepted cost is larger than "retried until it ages out", and worth
# stating plainly: without a DLQ there is no maxReceiveCount, so an asset that
# reliably kills whatever picks it up is retried for the full retention window
# by every worker that takes it, and EACH attempt copies a snapshot and
# attaches a volume before dying. That is money and EBS quota, not just wasted
# time. The stalled-queue alarm below does not catch it either: other messages
# keep draining, so NumberOfMessagesDeleted stays above zero. A poison asset
# is found by its repeated "asset scan finished" failures in the log group,
# joined by trace id.
resource "aws_sqs_queue" "scan" {
  name = "${local.name_prefix}-scan-queue"

  # Sized to ONE lease renewal interval, not to a whole scan. The daemon holds
  # its message by heartbeating ChangeMessageVisibility while the scan runs
  # (the daemon's default visibility timeout, extended on a ticker at about
  # a third of this). A flat 45-minute timeout would instead hide every
  # abandoned message for 45 minutes -- so a worker killed mid-scan would
  # block its asset for that long rather than releasing it promptly.
  visibility_timeout_seconds = 600

  # Must OUTLIVE the alarm window below. The previous design wanted short
  # retention AND an alarm on depth staying non-zero across several periods,
  # which are mutually exclusive: messages age out before the alarm fires and
  # the backlog silently clears itself. Four days covers a long weekend, so a
  # backlog that starts on a Friday is still there to be seen on Monday.
  message_retention_seconds = 345600

  # Long polling. The daemon asks for 20s waits; setting it here too means an
  # empty queue costs one request per 20s rather than a spin.
  receive_wait_time_seconds = 20

  sqs_managed_sse_enabled = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-scan-queue"
  })
}

# --- Dispatcher (enqueue-only) ----------------------------------------------

# Its OWN role, separate from the scanner's. A shared role would let a
# compromised scan of an untrusted disk image enqueue arbitrary work, which is
# exactly the escalation the producer/consumer split exists to prevent.
#
# Note what is absent: no EBS attach, no mount, no snapshot or volume
# creation, no secret read, and since the dispatcher launches nothing, no
# ecs:RunTask and no iam:PassRole.
# Two roles, because there are now two genuinely distinct principals: the one
# EventBridge Scheduler assumes to CALL RunInstances, and the one the
# instance RUNS AS. The ECS shape could fold them together because the task
# role and the RunTask caller were both consumed by the ECS service; splitting
# them here keeps the launcher unable to do discovery and the workload unable
# to launch anything.

# What the ephemeral instance runs as. Discovery and enqueue, nothing else.
# No snapshot, attach, delete or secret-read -- this is the unprivileged half
# of the producer/consumer split, and a compromise here reaches the scan queue
# but no asset data.
resource "aws_iam_role" "dispatcher" {
  count = var.enable_scan_schedule ? 1 : 0
  name  = "${local.name_prefix}-dispatcher-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EC2Assume"
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "dispatcher" {
  count = var.enable_scan_schedule ? 1 : 0
  name  = "${local.name_prefix}-dispatcher-policy"
  role  = aws_iam_role.dispatcher[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EnqueueScans"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.scan.arn
      },
      {
        # Discovery only. These three have no resource-level condition keys
        # in EC2, so "*" is the only expressible scope.
        Sid    = "DiscoverAssets"
        Effect = "Allow"
        Action = [
          "ec2:DescribeImages",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        # Ships this run's log and its exit code. Without it the instance
        # terminates silently and a failed discovery tick is invisible.
        Sid    = "ShipDispatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.scanner.arn}:*"
      },
      # DescribeLogGroups is called at agent startup and takes NO resource
      # qualifier -- it is a list operation over the account, so an ARN-scoped
      # Resource never matches and the call comes back AccessDenied. That
      # failure is silent by construction: log shipping is set up best-effort
      # so that it never aborts a discovery run, which means the instance
      # completes its work, terminates cleanly, and ships nothing.
      #
      # Read-only, and the only "*" on this role: it reveals log group names in
      # the account and grants nothing on their contents. The write actions
      # above stay pinned to this stack's group. The instance role carries the
      # same grant for the same reason.
      {
        Sid      = "DiscoverLogGroups"
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      }
    ]
  })
}

# What Scheduler assumes to launch the instance. It can start the dispatch
# template and pass the dispatch role -- and nothing else.
resource "aws_iam_role" "scheduler_dispatch" {
  count = var.enable_scan_schedule ? 1 : 0
  name  = "${local.name_prefix}-scheduler-dispatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SchedulerAssume"
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "scheduler.amazonaws.com" }
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "scheduler_dispatch" {
  count = var.enable_scan_schedule ? 1 : 0
  name  = "${local.name_prefix}-scheduler-dispatch-policy"
  role  = aws_iam_role.scheduler_dispatch[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # RunInstances takes no resource-level condition that can pin the
        # launch template itself, so the grant is scoped by the resources the
        # launch touches and then constrained by the PassRole statement below:
        # the only instance profile this role may pass is the dispatcher's, so
        # a launch it did not intend cannot acquire a useful identity.
        Sid    = "LaunchDispatchInstance"
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = [
          "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:volume/*",
          "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:network-interface/*",
          "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:security-group/*",
          "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:subnet/*",
          "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:launch-template/*",
          "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*"
        ]
      },
      {
        # Tagging is not optional: the account's tag policy denies an untagged
        # create outright, and the denial names the action rather than the
        # tags, so omitting this reads as a missing RunInstances permission.
        Sid      = "TagDispatchInstance"
        Effect   = "Allow"
        Action   = "ec2:CreateTags"
        Resource = "*"
        Condition = {
          StringEquals = { "ec2:CreateAction" = "RunInstances" }
        }
      },
      {
        # ONLY the dispatcher profile. Passing any other -- above all the
        # daemon's, which holds snapshot, attach, delete and secret-read --
        # would let a compromised scheduler role launch a privileged host.
        Sid      = "PassDispatcherProfile"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.dispatcher[0].arn
        Condition = {
          StringEquals = { "iam:PassedToService" = "ec2.amazonaws.com" }
        }
      }
    ]
  })
}

# A launch template of its own, deliberately NOT the daemon's. Discovery must
# not run on a host that mounts asset filesystems: the daemon instances attach
# and mount untrusted volumes, and keeping discovery off them is a
# blast-radius control, not a tidiness choice. An SSM RunCommand against the
# daemon ASG would have reused existing compute and was rejected for exactly
# this reason.
#
# Unprivileged and small: dispatch calls Describe* and SendMessage and touches
# no block device.
#
# The AMI is the same one the daemon runs, and that is the point -- the
# scanner AMI is the ONLY artifact shipped to customers. Running dispatch as a
# container would make the image a second artifact to publish, share and
# version, which is what this shape exists to avoid.
resource "aws_launch_template" "dispatch" {
  count         = var.enable_scan_schedule ? 1 : 0
  name_prefix   = "${local.name_prefix}-dispatch-"
  image_id      = local.scanner_image_id
  instance_type = var.dispatch_instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.dispatcher[0].arn
  }

  # The instance halts itself when dispatch finishes; this is what turns that
  # halt into a termination. Without it the instance stops and lingers,
  # billing EBS forever and never running again -- a stopped instance is not a
  # completed job.
  instance_initiated_shutdown_behavior = "terminate"

  # IMDSv2 required. The user_data makes no IMDS calls itself, but the AWS SDK
  # inside the binary resolves credentials through it.
  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  vpc_security_group_ids = [aws_security_group.dispatch[0].id]

  user_data = base64encode(templatefile("${path.module}/templates/dispatch-user-data.sh.tftpl", {
    aws_region     = var.aws_region
    scan_queue_url = aws_sqs_queue.scan.url
    log_group      = aws_cloudwatch_log_group.scanner.name
    log_level      = var.scan_log_level
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, { Name = "${local.name_prefix}-dispatch" })
  }

  # RunInstances creates the root volume as a separately taggable resource and
  # the account's tag policy applies to it independently, so omitting this
  # block denies the whole launch.
  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.common_tags, { Name = "${local.name_prefix}-dispatch" })
  }

  tags = local.common_tags
}

# Egress only, and no ingress at all: dispatch calls the EC2 and SQS APIs and
# accepts no connections. Nothing should ever reach this host.
resource "aws_security_group" "dispatch" {
  count       = var.enable_scan_schedule ? 1 : 0
  name_prefix = "${local.name_prefix}-dispatch-"
  description = "Ephemeral dispatch instance: outbound AWS API calls only"
  vpc_id      = module.network.vpc_id

  egress {
    description = "Outbound to AWS APIs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-dispatch" })
}

resource "aws_iam_instance_profile" "dispatcher" {
  count = var.enable_scan_schedule ? 1 : 0
  name  = "${local.name_prefix}-dispatcher-profile"
  role  = aws_iam_role.dispatcher[0].name

  tags = local.common_tags
}

# EventBridge Scheduler runs the dispatcher on a cadence. The target launches
# ONE throwaway EC2 instance from the scanner AMI, which discovers tagged
# assets, sends one message per asset to the scan queue, and halts itself.
#
# Scheduler's universal target calls the EC2 API directly, so there is no
# Lambda and no container in between. The instance IS the job: it exists for
# the length of one discovery run and terminates on shutdown.
#
# Discovery deliberately does NOT run on the daemon instances. Doing so would
# give hosts that mount untrusted filesystems ec2:Describe* over the account,
# and would create a leader-election problem where only one discoverer should
# run per tick. A separate instance has neither.
resource "aws_scheduler_schedule" "dispatch" {
  count      = var.enable_scan_schedule ? 1 : 0
  name       = "${local.name_prefix}-dispatch"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = var.scan_schedule_expression
  schedule_expression_timezone = var.scan_schedule_timezone

  target {
    arn      = "arn:${data.aws_partition.current.partition}:scheduler:::aws-sdk:ec2:runInstances"
    role_arn = aws_iam_role.scheduler_dispatch[0].arn

    # The launch template carries the AMI, the instance profile, the user_data
    # and the shutdown behaviour, so the call itself only has to say "one, from
    # that template, in that subnet". Pinning $Latest rather than a fixed
    # version means an applied template change takes effect on the next tick
    # without touching this resource.
    input = jsonencode({
      LaunchTemplate = {
        LaunchTemplateId = aws_launch_template.dispatch[0].id
        Version          = "$Latest"
      }
      MinCount = 1
      MaxCount = 1
      SubnetId = module.network.subnet_ids[0]
    })

    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 3
    }
  }
}

# --- Scaling on queue backlog -----------------------------------------------

# Target tracking on BACKLOG PER INSTANCE (queue depth divided by in-service
# instances), not on raw depth. Raw depth scales badly: at depth 100 against
# asg_max_size 2 it pins at max and stops saying anything about per-worker
# load, so the policy cannot tell "two workers, deep backlog" from "twenty
# workers, deep backlog".
#
# Expressed as metric math because CloudWatch publishes no such metric: m1+m2
# is outstanding work (visible plus in-flight), m3 is in-service instances,
# and the expression divides them. The clamp matters -- at asg_min_size 0 the
# fleet really does reach zero instances, and an unguarded divide by zero
# yields no datapoint, which target tracking treats as "no signal" and holds
# capacity at zero forever while the queue fills.
#
# IF(m3 > 0, m3, 1), NOT MAX(m3, 1). CloudWatch's MAX is an AGGREGATE over one
# time series -- the maximum across its datapoints -- not a two-argument
# maximum, so MAX(m3, 1) is rejected at PutScalingPolicy with "Unsupported
# operand type(s) for MAX: [TimeSeries, Scalar]". Verified against
# GetMetricData: backlog 6 over 0 instances yields 6 (scale out), over 3
# instances yields 2.
resource "aws_autoscaling_policy" "scan_backlog" {
  name                   = "${local.name_prefix}-scan-backlog"
  autoscaling_group_name = aws_autoscaling_group.ecs_instances.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    # One asset of backlog per instance. The daemon scans one asset at a time,
    # so this says "roughly one queued asset waiting per worker" -- above it,
    # add a worker.
    target_value = 1.0

    customized_metric_specification {
      metrics {
        id    = "backlog_per_instance"
        label = "Outstanding scans per in-service instance"
        # IF(m3 > 0, m3, 1): see the divide-by-zero note above.
        expression  = "(m1 + m2) / IF(m3 > 0, m3, 1)"
        return_data = true
      }

      # Visible AND in-flight. Counting only visible messages would read 0
      # whenever every worker is mid-scan holding its message -- which is
      # exactly a saturated fleet -- and the policy would scale IN, straight
      # into the lifecycle hook, killing scans that then redeliver and get
      # redone. In-flight work is still outstanding work.
      metrics {
        id          = "m1"
        return_data = false
        metric_stat {
          metric {
            namespace   = "AWS/SQS"
            metric_name = "ApproximateNumberOfMessagesVisible"
            dimensions {
              name  = "QueueName"
              value = aws_sqs_queue.scan.name
            }
          }
          stat = "Average"
        }
      }

      metrics {
        id          = "m2"
        return_data = false
        metric_stat {
          metric {
            namespace   = "AWS/SQS"
            metric_name = "ApproximateNumberOfMessagesNotVisible"
            dimensions {
              name  = "QueueName"
              value = aws_sqs_queue.scan.name
            }
          }
          stat = "Average"
        }
      }

      metrics {
        id          = "m3"
        return_data = false
        metric_stat {
          metric {
            namespace   = "AWS/AutoScaling"
            metric_name = "GroupInServiceInstances"
            dimensions {
              name  = "AutoScalingGroupName"
              value = aws_autoscaling_group.ecs_instances.name
            }
          }
          stat = "Average"
        }
      }
    }
  }
}

# Scale-in must not kill a scan in progress. The hook holds a terminating
# instance in Terminating:Wait, where the daemon's SIGTERM handler abandons
# the in-flight scan and runs cleanup -- detaching the volume and deleting the
# copied snapshot, which are the artifacts that leak money and quota silently.
# The message is left queued, so the asset redelivers and another worker
# takes it.
#
# heartbeat_timeout is sized to CLEANUP, not to a scan: waiting out a
# 45-minute scan to avoid work that redelivery will simply redo buys nothing.
# CONTINUE on timeout, so a hung cleanup still terminates rather than wedging
# the ASG.
resource "aws_autoscaling_lifecycle_hook" "scan_drain" {
  name                   = local.scan_drain_hook_name
  autoscaling_group_name = aws_autoscaling_group.ecs_instances.name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  heartbeat_timeout      = 300
  default_result         = "CONTINUE"
}

# Grants the instance the right to say "cleanup is done, proceed" rather than
# waiting out the full heartbeat_timeout. Without it a scale-in where cleanup
# finished in ten seconds still holds the instance for five minutes, and the
# ASG cannot replace capacity while it waits.
resource "aws_iam_role_policy" "ecs_instance_lifecycle" {
  name = "${local.name_prefix}-instance-lifecycle"
  role = aws_iam_role.ecs_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CompleteScanDrain"
        Effect   = "Allow"
        Action   = "autoscaling:CompleteLifecycleAction"
        Resource = aws_autoscaling_group.ecs_instances.arn
      }
    ]
  })
}

# --- Alarm ------------------------------------------------------------------

# Depth AND throughput together, because depth alone does not catch the
# failure that matters. A deep queue being actively drained is healthy; a
# queue of one message with every worker wedged is not, and depth cannot tell
# them apart. This fires on "work outstanding, nothing progressing" -- the
# shape of a silently idle fleet: a failed image pull, a broken daemon, an
# ASG that cannot launch.
#
# Evaluated over 3 periods of 5 minutes so a brief gap between one scan
# finishing and the next starting does not trip it.
resource "aws_cloudwatch_metric_alarm" "scan_queue_stalled" {
  alarm_name        = "${local.name_prefix}-scan-queue-stalled"
  alarm_description = "Scan queue has work outstanding while no messages are being consumed -- the fleet is idle or wedged, not merely busy."

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 3

  # Missing data is NOT a breach: an empty queue publishes no datapoints at
  # all, and treating that as an alarm would fire on every idle account.
  treat_missing_data = "notBreaching"

  metric_query {
    id          = "stalled"
    label       = "Outstanding work with zero throughput"
    expression  = "IF(deleted < 1, visible, 0)"
    return_data = true
  }

  metric_query {
    id          = "visible"
    return_data = false
    metric {
      namespace   = "AWS/SQS"
      metric_name = "ApproximateNumberOfMessagesVisible"
      dimensions  = { QueueName = aws_sqs_queue.scan.name }
      period      = 300
      stat        = "Maximum"
    }
  }

  metric_query {
    id          = "deleted"
    return_data = false
    metric {
      namespace   = "AWS/SQS"
      metric_name = "NumberOfMessagesDeleted"
      dimensions  = { QueueName = aws_sqs_queue.scan.name }
      period      = 300
      stat        = "Sum"
    }
  }

  alarm_actions = local.sns_topic_arn != "" ? [local.sns_topic_arn] : []
  tags          = local.common_tags
}

# Catches the CLASS of defect, not its instances: an in-service fleet whose
# log group receives nothing.
#
# The scanner's log shipping has several independent ways to fail silently --
# a rejected CloudWatch agent config, a missing logs:DescribeLogGroups grant,
# an absent agent, a full root volume -- and all of them share one shape.
# user_data's `fetch-config` is best effort by design, because a failed
# forwarder must not abort the boot that writes the systemd unit. So every one
# of those faults degrades to a warning nobody reads: the instance boots,
# registers, reports healthy, and ships nothing. Three such defects were found
# in review of the AMI-baking change; this alarm is what would have caught
# them without reading any of the code.
#
# Deliberately NOT covered by scan_queue_stalled above. That one asks "is work
# progressing", which stays healthy here -- scans still run and still write
# their reports to S3. What is lost is the ability to SEE them: the scan
# follow tooling locates a scan by filtering this log group for a trace
# id, so an instance shipping nothing makes every scan it runs unobservable
# while appearing to work.
#
# IF(instances > 0, ...) is the precondition: a scaled-to-zero fleet publishes
# no log events and that is correct, not a fault. Only silence WHILE instances
# are in service is a fault. Both halves must be present for the expression to
# evaluate, which is why enabled_metrics is set on the ASG above -- group
# metrics are opt-in and GroupInServiceInstances is otherwise absent entirely.
#
# 3 x 5 minutes, matching scan_queue_stalled: an idle daemon long-polling an
# empty queue still emits startup and poll lines, so a quarter hour of total
# silence from a live instance is a fault rather than a quiet patch.
resource "aws_cloudwatch_metric_alarm" "daemon_logs_silent" {
  alarm_name        = "${local.name_prefix}-daemon-logs-silent"
  alarm_description = "Instances are in service but the scanner log group is receiving no events -- log shipping is broken, so scans are unobservable even if they are running."

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 3

  # An ASG at zero publishes no GroupInServiceInstances datapoints, which must
  # not read as a breach.
  treat_missing_data = "notBreaching"

  metric_query {
    id          = "silent"
    label       = "In-service instances shipping no logs"
    expression  = "IF(instances > 0 AND events < 1, instances, 0)"
    return_data = true
  }

  metric_query {
    id          = "instances"
    return_data = false
    metric {
      namespace   = "AWS/AutoScaling"
      metric_name = "GroupInServiceInstances"
      dimensions  = { AutoScalingGroupName = local.asg_name }
      period      = 300
      stat        = "Minimum"
    }
  }

  # Sum, not Average: one instance shipping while another is mute still yields
  # a non-zero sum, so this fires only on TOTAL silence. A per-instance signal
  # would need a metric filter per stream, which is not worth the cost here --
  # total silence is the failure that hides a broken deployment.
  metric_query {
    id          = "events"
    return_data = false
    metric {
      namespace   = "AWS/Logs"
      metric_name = "IncomingLogEvents"
      dimensions  = { LogGroupName = aws_cloudwatch_log_group.scanner.name }
      period      = 300
      stat        = "Sum"
    }
  }

  alarm_actions = local.sns_topic_arn != "" ? [local.sns_topic_arn] : []
  tags          = local.common_tags
}
