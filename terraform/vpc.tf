# VPC with public + private subnets for isolated LLM tool testing

resource "aws_vpc" "harness" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "fingerprint-harness-vpc" }
}

# --- Public subnet (bastion, NAT gateway, proxy) ---

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.harness.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "harness-public" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.harness.id
  tags   = { Name = "harness-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.harness.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "harness-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --- Private subnet (honeypot, capture, tools) ---

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.harness.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "harness-private" }
}

# NAT Gateway for private subnet outbound (tools → LLM APIs via proxy)
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "harness-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  tags = { Name = "harness-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.harness.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = { Name = "harness-private-rt" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# --- VPC Flow Logs ---

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.harness.id
  traffic_type         = "ALL"
  log_destination      = aws_s3_bucket.flowlogs.arn
  log_destination_type = "s3"

  tags = { Name = "harness-flowlogs" }
}

resource "aws_s3_bucket" "flowlogs" {
  bucket_prefix = "fingerprint-harness-flowlogs-"
  force_destroy = true

  tags = { Name = "harness-flowlogs" }
}
