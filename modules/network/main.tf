data "aws_vpc" "this" {
  id = var.vpc_id
}

data "aws_subnet" "this" {
  for_each = toset(var.subnet_ids)
  id       = each.value
}
