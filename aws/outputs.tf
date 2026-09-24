output "s3_results_bucket" {
  description = "S3 bucket for storing scan results"
  value       = aws_s3_bucket.results.id
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.scanner.name
}

output "task_role_arn" {
  description = "ARN of the task runtime role"
  value       = aws_iam_role.ecs_task.arn
}

output "scanner_deploy_role_arn" {
  description = "IAM role ARN operators/CI assume to run the scanner list command (ec2:DescribeImages). Empty unless deploy_role_trusted_principal_arns is set."
  value       = length(var.deploy_role_trusted_principal_arns) > 0 ? aws_iam_role.scanner_deploy[0].arn : ""
}

output "asg_name" {
  description = "Name of the Auto Scaling Group backing the ECS cluster's EC2 capacity"
  value       = aws_autoscaling_group.ecs_instances.name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule that starts a scan task when an AMI becomes available (empty when disabled)"
  value       = var.enable_eventbridge_trigger ? aws_cloudwatch_event_rule.ami_available[0].arn : ""
}

output "scan_trigger_tag" {
  description = "The tag an administrator must set on an AMI for it to be scanned. The trigger starts a task for every AMI that becomes available; the scanner skips any that does not carry this tag. Reserved in the binary and not configurable. Empty when the EventBridge trigger is disabled."
  value       = var.enable_eventbridge_trigger ? "RLScan=true" : ""
}

output "reversinglabs_api_url" {
  description = "ReversingLabs Spectra Detect host the scanner task submits to"
  value       = var.reversinglabs_api_url
}

output "reversinglabs_api_token_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the RL API token, whether created here or supplied via var.reversinglabs_api_token_secret_arn"
  value       = local.reversinglabs_api_token_secret_arn
}

output "sns_alert_topic_arn" {
  description = "ARN of the SNS topic the scanner publishes detection notifications to, whether created here or supplied via var.sns_alert_topic_arn. Empty when the SNS output action is disabled. Attach a subscriber to this without reading state."
  value       = local.sns_topic_arn
}

output "sns_alert_subscription_arn" {
  description = "ARN of the optional subscription on the managed topic. Empty when none was requested. An email subscription is pending until the recipient confirms it -- a non-empty ARN here does not mean mail is being delivered."
  value       = var.create_sns_topic && var.sns_subscription_protocol != "" ? aws_sns_topic_subscription.alerts[0].arn : ""
}

output "scan_queue_url" {
  description = "URL of the SQS scan queue. Send scan request messages here; also exported to the scanner as SCANNER_SCAN_QUEUE_URL."
  value       = aws_sqs_queue.scan.url
}

output "scan_queue_arn" {
  description = "ARN of the SQS scan queue"
  value       = aws_sqs_queue.scan.arn
}

output "dispatcher_role_arn" {
  description = "IAM role ARN the scheduled dispatcher assumes (sqs:SendMessage on the scan queue plus ec2:Describe* for discovery). Empty unless enable_scan_schedule is set."
  value       = var.enable_scan_schedule ? aws_iam_role.dispatcher[0].arn : ""
}
