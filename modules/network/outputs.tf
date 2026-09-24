output "vpc_id" {
  description = "VPC ID (validated to exist via data source lookup)"
  value       = data.aws_vpc.this.id
}

output "subnet_ids" {
  description = "Subnet IDs (validated to exist via data source lookup)"
  value       = [for s in data.aws_subnet.this : s.id]
}
