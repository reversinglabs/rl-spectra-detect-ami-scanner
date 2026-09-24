variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use. No default -- pass your own account's profile name explicitly."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID to deploy into, forwarded to ../modules/network. No default -- pass your own account's VPC ID explicitly."
  type        = string
}

variable "subnet_ids" {
  description = "Public subnet IDs within var.vpc_id, forwarded to ../modules/network. No default -- pass your own account's subnet IDs explicitly."
  type        = list(string)
}

variable "environment" {
  description = "Environment name. Feeds local.name_prefix, so it appears in every resource name -- changing it renames the whole stack. Distinct from any Environment tag set via var.resource_tags, which does not affect names."
  type        = string
  default     = "dev"
}

# --- Resource tags ----------------------------------------------------------
# Every resource this stack creates carries local.common_tags. The stack sets
# Name, Project, Method and ManagedBy itself; everything else comes from
# var.resource_tags.
#
# An account may enforce a tag policy requiring particular keys (Environment,
# Owner, CostCenter and the like). Such a denial does NOT look like a tag
# problem: it is a bare AccessDenied / UnauthorizedOperation naming the action,
# so it reads as a missing IAM permission. If a create is denied and the IAM
# policy looks correct, suspect a required tag before debugging IAM.

variable "resource_tags" {
  description = "Extra tags applied to every resource the stack creates, and to the EBS snapshots and volumes the scanner creates at runtime. Set whatever your account's tag policy and cost-allocation scheme require, e.g. { Environment = \"prod\", Owner = \"security\" }. The stack's own Name, Project, Method and ManagedBy tags win a key collision."
  type        = map(string)
  default     = {}
}

variable "tag_project" {
  description = "Value of the Project tag. Load-bearing, not cosmetic: the task role grants ec2:AttachVolume/DetachVolume only on instances carrying it, so it must match on the scanner instances and is not safe to set per-resource."
  type        = string
  default     = "detect-ami-scanner"
}

variable "reversinglabs_api_url" {
  description = "ReversingLabs Spectra Detect host (config key reversinglabs.api_url), e.g. https://spectra-detect.example.com. May be a single Worker or a Hub; a Hub also needs reversinglabs_allowed_task_hosts. No default -- pass your own account's host explicitly."
  type        = string
}

variable "reversinglabs_allowed_task_hosts" {
  description = "Worker hosts, besides the reversinglabs_api_url host itself, whose task URLs the scanner may poll (config key reversinglabs.allowed_task_hosts). Only needed when reversinglabs_api_url is a Hub: the Hub names the Worker holding each report, and polling it sends the API token there, so hosts must be accepted explicitly. Matched by hostname, port ignored. An entry is an exact host, a leading-dot domain suffix (\".workers.internal\") that covers a pool as it scales, or \"*\" to trust any host the Hub names. Empty means only the api_url host is polled."
  type        = list(string)
  default     = []
}

# Two ways to supply the token, exactly one of which must be used:
#   - reversinglabs_api_token: terraform creates the secret from this value
#   - reversinglabs_api_token_secret_arn: point at a secret you already own
variable "reversinglabs_api_token" {
  description = "ReversingLabs Spectra Detect API token (config key reversinglabs.api_token). Terraform creates a Secrets Manager secret holding this value -- never write it to a config file or commit it. Pass via -var or TF_VAR_reversinglabs_api_token so it never lands in shell history or a tfvars file you might commit. Leave empty to reuse an existing secret via reversinglabs_api_token_secret_arn instead."
  type        = string
  sensitive   = true
  default     = ""
}

variable "reversinglabs_api_token_secret_arn" {
  description = "ARN of an existing Secrets Manager secret containing the RL API token. Leave empty to have terraform create one from reversinglabs_api_token."
  type        = string
  default     = ""

  validation {
    condition     = var.reversinglabs_api_token_secret_arn == "" || can(regex("^arn:aws:secretsmanager:", var.reversinglabs_api_token_secret_arn))
    error_message = "reversinglabs_api_token_secret_arn must be a valid Secrets Manager ARN (arn:aws:secretsmanager:...) or empty."
  }

  validation {
    condition     = !(var.reversinglabs_api_token != "" && var.reversinglabs_api_token_secret_arn != "")
    error_message = "Set either reversinglabs_api_token (terraform creates the secret) or reversinglabs_api_token_secret_arn (reuse an existing one), not both."
  }

  validation {
    condition     = var.reversinglabs_api_token != "" || var.reversinglabs_api_token_secret_arn != ""
    error_message = "The scanner cannot authenticate without a token: set reversinglabs_api_token, or reversinglabs_api_token_secret_arn to reuse an existing secret."
  }
}

variable "deploy_role_trusted_principal_arns" {
  description = "IAM principal ARNs (operator roles/users or a CI role) allowed to assume the scanner deploy-time role. Empty by default, which skips creating the role entirely -- IAM rejects a trust policy with no principals. Set it to use `scanner deploy`/`list`."
  type        = list(string)
  default     = []
}

# SNS detection notifications. Two mutually exclusive ways to get a topic:
# let this stack create one (create_sns_topic), or point at one you already
# own (sns_alert_topic_arn). Setting both is an error rather than a silent
# precedence order -- an operator who supplies an ARN and also asks for a
# managed topic has one of the two wrong, and guessing which would publish
# notifications to a topic nobody is subscribed to.
variable "create_sns_topic" {
  description = "Create an SNS topic for detection notifications and point the scanner at it. Mutually exclusive with sns_alert_topic_arn. The topic is encrypted (see sns_topic_kms_master_key_id) because a detection notification names malicious paths inside a customer AMI."
  type        = bool
  default     = false

  validation {
    condition     = !(var.create_sns_topic && var.sns_alert_topic_arn != "")
    error_message = "create_sns_topic and sns_alert_topic_arn are mutually exclusive: either this stack creates the topic or you supply an existing ARN, not both."
  }
}

variable "sns_alert_topic_arn" {
  description = "ARN of an existing SNS topic the scanner publishes detection notifications to (config key output.sns.topic_arn). Empty by default -- set it only when enabling the SNS output action, which grants the task sns:Publish on this topic. Mutually exclusive with create_sns_topic."
  type        = string
  default     = ""

  validation {
    condition     = var.sns_alert_topic_arn == "" || can(regex("^arn:aws:sns:", var.sns_alert_topic_arn))
    error_message = "sns_alert_topic_arn must be a valid SNS topic ARN (arn:aws:sns:...) or empty."
  }
}

variable "sns_topic_kms_master_key_id" {
  description = <<-EOT
    KMS key for the managed SNS topic's server-side encryption. Exactly two forms are accepted:

      - the literal string "alias/aws/sns" (the default), for the AWS-managed key -- no key policy
        and no extra task-role grants needed, but cross-account subscribers cannot use it;
      - a full customer-managed key ARN (arn:aws:kms:...:key/...), for cross-account subscribers or
        your own rotation policy. The task role is then also granted kms:GenerateDataKey/kms:Decrypt
        on it; without those, Publish fails at runtime rather than at plan time.

    A bare key ID or a non-"alias/aws/sns" alias is rejected: neither can be used as an IAM policy
    Resource, so the KMS grant would silently match nothing and reproduce the very runtime failure
    the grant exists to prevent. Resolve an alias to its key ARN before passing it here.

    Note that only the exact string "alias/aws/sns" is recognised as the AWS-managed key. Any other
    spelling of that same key is treated as customer-managed, and the stack will try to grant KMS on
    a key whose policy cannot be edited. Use the literal default.

    Ignored unless create_sns_topic is true.
  EOT
  type        = string
  default     = "alias/aws/sns"

  validation {
    condition     = var.sns_topic_kms_master_key_id != ""
    error_message = "sns_topic_kms_master_key_id must not be empty -- an unencrypted topic is not an option here, since a detection notification names malicious paths inside a customer AMI. Use alias/aws/sns for the AWS-managed default."
  }

  # The value is used verbatim as an IAM policy Resource for the KMS grant, and
  # only an ARN works there. An alias or a bare key ID would produce a grant
  # that matches nothing -- IAM accepts the statement, and Publish then fails at
  # runtime with a KMS AccessDenied, which is exactly what the grant is for.
  validation {
    condition = (
      var.sns_topic_kms_master_key_id == "alias/aws/sns" ||
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/", var.sns_topic_kms_master_key_id))
    )
    error_message = "sns_topic_kms_master_key_id must be either the literal \"alias/aws/sns\" or a full customer-managed key ARN (arn:aws:kms:<region>:<account>:key/<id>). An alias or a bare key ID cannot be used as an IAM policy Resource, so the task role's KMS grant would match nothing and Publish would fail at runtime."
  }
}

variable "sns_subscription_protocol" {
  description = "Protocol for an optional subscription on the managed SNS topic: email, email-json, https, sms, or empty to create none. Wiring a subscriber here avoids a second manual step after apply. An email subscription is pending until the recipient confirms it -- terraform reports it as created either way."
  type        = string
  default     = ""

  validation {
    condition     = contains(["", "email", "email-json", "https", "sms"], var.sns_subscription_protocol)
    error_message = "sns_subscription_protocol must be one of: email, email-json, https, sms, or empty."
  }
}

variable "sns_subscription_endpoint" {
  description = "Endpoint for the optional managed-topic subscription: an email address, an https:// URL, or a phone number, matching sns_subscription_protocol."
  type        = string
  default     = ""

  validation {
    condition     = (var.sns_subscription_protocol == "") == (var.sns_subscription_endpoint == "")
    error_message = "sns_subscription_protocol and sns_subscription_endpoint must be set together, or both left empty."
  }
}

variable "instance_type" {
  description = "EC2 instance type for ECS container instances"
  type        = string
  default     = "t3.medium"
}

variable "scanner_ami_id" {
  description = <<-EOT
    AMI for the ECS container instances. Built by Packer from a git-tagged commit
    on master (packer/scanner-ami.pkr.hcl) and carrying the scanner binary, the
    AWS CLI and the filesystem tooling the scan path needs, so the daemon starts
    with no boot-time network dependency at all.

    Empty (the default) falls back to the AL2023 ECS-optimised AMI resolved from
    SSM. That fallback boots and registers with the cluster, but has NO scanner
    binary, so the daemon unit fails to start and the instance never scans -- it
    exists so the stack can be applied before the first AMI is built, not as a
    working configuration.

    Updating this is a fleet-visible change: it makes a new launch template
    version, and the ASG only picks it up on an instance refresh. Mid-refresh the
    fleet runs two AMIs, so one scan window can produce reports carrying
    different scanner_version values. That is inherent to a rolling refresh.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.scanner_ami_id == "" || can(regex("^ami-[0-9a-f]{8,17}$", var.scanner_ami_id))
    error_message = "scanner_ami_id must be empty or a valid AMI id (ami- followed by 8-17 hex characters)."
  }
}

variable "asg_min_size" {
  description = "Minimum number of EC2 instances in the ECS ASG"
  type        = number
  default     = 0
}

variable "asg_max_size" {
  description = "Maximum number of EC2 instances in the ECS ASG"
  type        = number
  default     = 2
}

variable "asg_desired_capacity" {
  description = "Desired number of EC2 instances in the ECS ASG"
  type        = number
  default     = 1
}

variable "enable_scan_schedule" {
  description = "Create an EventBridge schedule that runs the enqueue-only dispatcher, discovering tagged assets and putting one scan message each on the scan queue. Off by default so applying the stack never silently begins scanning, matching enable_eventbridge_trigger."
  type        = bool
  default     = false
}

variable "scan_schedule_timezone" {
  description = "IANA timezone the schedule expression is interpreted in, e.g. Europe/Zagreb. Only meaningful for a cron() expression: a rate() fires relative to when the schedule was created and has no clock time at all. A named zone rather than a fixed offset so daylight saving is handled -- pinning UTC would move a local-time run by an hour twice a year."
  type        = string
  default     = "UTC"
}

variable "scan_schedule_expression" {
  description = "How often the dispatcher runs when enable_scan_schedule is true. Daily by default, as rate(1 day), which fires 24h after the schedule is CREATED and every 24h after -- it has no fixed hour, so the time of day is whatever minute the apply happened to run. Use a cron() expression with scan_schedule_timezone for a specific local hour, e.g. cron(0 3 * * ? *) for 03:00. NOTE: there is no per-asset scan history and no dedup, so every run re-enqueues every tagged asset it discovers. Keep this slower than a full run takes to drain, or a run firing mid-backlog queues those assets again and they are scanned more than once. That is an accepted limitation rather than a pending fix."
  type        = string
  default     = "rate(1 day)"
}

variable "daemon_max_scans" {
  description = "Assets one daemon process handles before exiting cleanly. 0 is unbounded, which is the deployed default: systemd restarts the unit, so a low value here only churns containers. 1 restores a per-asset container boundary at the cost of a restart between every scan -- the isolation trade-off is a restart between scans versus a shared process."
  type        = number
  default     = 0

  validation {
    condition     = var.daemon_max_scans >= 0
    error_message = "daemon_max_scans must be 0 (unbounded) or positive."
  }
}

variable "daemon_idle_timeout" {
  description = "How long the daemon keeps long-polling an empty scan queue before exiting. The deployed default is long because the unit is restarted by systemd: exiting on a dry queue would make RestartSec the real polling interval, paying a container start and a full preflight for every poll. 0 exits on the first empty poll, which is one-shot behaviour and wrong for a service."
  type        = string
  default     = "55m"
}

variable "enable_eventbridge_trigger" {
  description = "Create an EventBridge rule that enqueues a scan message whenever an AMI becomes available. The scanner then scans only those AMIs carrying the reserved RLScan=true tag. Off by default so applying the stack never silently begins scanning. Combines freely with enable_scan_schedule -- both are queue producers."
  type        = bool
  default     = false
}

# Scanning is opt-in per AMI, but the tag is checked by the scanner, not by the
# EventBridge rule. The rule fires on AMI readiness ("EC2 AMI State Change",
# state available), and that event carries only ImageId and State -- it has no
# tag data, so an event pattern has nothing to match against. Triggering on the
# tag-change event instead would filter natively but would require tagging at
# exactly the right moment and would miss any AMI tagged before it finished
# building.
#
# The consequence: every new AMI starts a task, and an untagged one exits with
# code 4 in seconds without copying a snapshot. Cheap, but not free -- a burst
# of AMI creation causes a burst of short-lived tasks.
variable "scan_log_level" {
  description = "SCANNER_LOG_LEVEL for scans, both the task definition's default and EventBridge-triggered runs."
  type        = string
  default     = "info"

  validation {
    condition     = contains(["debug", "info", "warn", "error"], var.scan_log_level)
    error_message = "scan_log_level must be one of: debug, info, warn, error."
  }
}

variable "dispatch_instance_type" {
  description = "Instance type for the ephemeral dispatch instance. Discovery makes a handful of API calls and exits, so the smallest generally-available type is enough; it is billed per second for the lifetime of one run."
  type        = string
  default     = "t3.micro"
}

# Scanner file filters. What each one does, and how the two stages interact, is
# documented under "File filters" in ../README.md.
#
# Leaving one at its default omits the variable from the daemon's unit entirely
# rather than setting an empty value, so the scanner's own default applies.

variable "scan_mode" {
  description = "Which directories a scan walks: binary-focused, critical-paths, or full-filesystem. A path filter only -- it never inspects file contents."
  type        = string
  default     = "full-filesystem"

  validation {
    condition     = contains(["binary-focused", "critical-paths", "full-filesystem"], var.scan_mode)
    error_message = "scan_mode must be one of: binary-focused, critical-paths, full-filesystem."
  }
}

variable "scan_exclude_categories" {
  description = "File categories to drop, by MIME type detected from magic bytes. One or more of: archive, audio, document, font, image, video."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.scan_exclude_categories : contains(["archive", "audio", "document", "font", "image", "video"], c)])
    error_message = "scan_exclude_categories entries must each be one of: archive, audio, document, font, image, video."
  }
}

variable "scan_include_categories" {
  description = "If set, keep only files in these categories, using the same six names as scan_exclude_categories. Exclusions are evaluated first."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.scan_include_categories : contains(["archive", "audio", "document", "font", "image", "video"], c)])
    error_message = "scan_include_categories entries must each be one of: archive, audio, document, font, image, video."
  }
}

variable "scan_exclude_mime" {
  description = "Drop files whose detected MIME type contains any of these substrings. A plain substring test, not anchored: \"image/\" also matches a type merely containing it."
  type        = list(string)
  default     = []
}

variable "scan_include_mime" {
  description = "If set, keep only files whose detected MIME type contains one of these substrings."
  type        = list(string)
  default     = []
}

variable "scan_exclude_paths" {
  description = "Path patterns to skip, applied on top of the scan mode."
  type        = list(string)
  default     = []
}

variable "scan_include_paths" {
  description = "If set, walk only these paths, narrowing whatever the scan mode selected."
  type        = list(string)
  default     = []
}

variable "scan_file_extensions" {
  description = "If set, keep only files carrying one of these extensions, written without the leading dot and matched case-insensitively against the filename."
  type        = list(string)
  default     = []
}

variable "scan_max_files" {
  description = "Cap on how many files one scan uploads. 0 means no cap. A scan that reaches the cap is recorded in its report as truncated."
  type        = number
  default     = 0

  validation {
    condition     = var.scan_max_files >= 0
    error_message = "scan_max_files must not be negative; 0 means no cap."
  }
}

variable "scan_max_file_size" {
  description = "Largest file a scan uploads, in bytes. 0 means no limit."
  type        = number
  default     = 0

  validation {
    condition     = var.scan_max_file_size >= 0
    error_message = "scan_max_file_size must not be negative; 0 means no limit."
  }
}

variable "scan_min_file_size" {
  description = "Smallest file a scan uploads, in bytes. Defaults to the scanner's own floor; 0 uploads files of any size, including empty ones."
  type        = number
  default     = 100

  validation {
    condition     = var.scan_min_file_size >= 0
    error_message = "scan_min_file_size must not be negative."
  }
}
