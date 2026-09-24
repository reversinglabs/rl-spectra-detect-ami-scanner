variable "vpc_id" {
  description = "VPC ID to look up. No default -- pass your own account's VPC ID explicitly (e.g. via -var or a gitignored terraform.tfvars) so this source tree never bakes in a specific AWS account's topology."
  type        = string
}

variable "subnet_ids" {
  description = "Public subnet IDs within var.vpc_id to look up. No default -- pass your own account's subnet IDs explicitly."
  type        = list(string)
}
