# Security groups — per-tool egress filtering

# Bastion SG (public subnet, SSH only)
resource "aws_security_group" "bastion" {
  name_prefix = "harness-bastion-"
  vpc_id      = aws_vpc.harness.id
  description = "SSH access from operator IP"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
    description = "SSH from operator"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Unrestricted outbound"
  }

  tags = { Name = "harness-bastion-sg" }
}

# Honeypot SG (private subnet, accepts tool connections)
resource "aws_security_group" "honeypot" {
  name_prefix = "harness-honeypot-"
  vpc_id      = aws_vpc.harness.id
  description = "Honeypot — accepts TLS from tools, SSH from bastion"

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["10.0.2.0/24"]
    description = "TLS from tools in private subnet"
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.2.0/24"]
    description = "HTTP health check"
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
    description     = "SSH from bastion"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "harness-honeypot-sg" }
}

# Proxy SG (public subnet, Squid with domain-based ACLs)
resource "aws_security_group" "proxy" {
  name_prefix = "harness-proxy-"
  vpc_id      = aws_vpc.harness.id
  description = "Squid proxy — domain-filtered outbound for LLM API access"

  ingress {
    from_port   = 3128
    to_port     = 3128
    protocol    = "tcp"
    cidr_blocks = ["10.0.2.0/24"]
    description = "Squid from private subnet tools"
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
    description     = "SSH from bastion"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to LLM APIs (filtered by Squid ACLs)"
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS resolution"
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS resolution (TCP)"
  }

  tags = { Name = "harness-proxy-sg" }
}

# Tool SG (private subnet, restricted egress)
# Tools can ONLY reach: honeypot (8443), proxy (3128), DNS
resource "aws_security_group" "tool" {
  name_prefix = "harness-tool-"
  vpc_id      = aws_vpc.harness.id
  description = "LLM pentest tools — egress only to honeypot + proxy"

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
    description     = "SSH from bastion"
  }

  # Honeypot access
  egress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["10.0.2.0/24"]
    description = "TLS to honeypot"
  }

  # Proxy access (for LLM API calls)
  egress {
    from_port       = 3128
    to_port         = 3128
    protocol        = "tcp"
    security_groups = [aws_security_group.proxy.id]
    description     = "Squid proxy for LLM API access"
  }

  # DNS (needed for hostname resolution even through proxy)
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS"
  }

  tags = { Name = "harness-tool-sg" }
}
