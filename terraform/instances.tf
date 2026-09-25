# EC2 instances — honeypot, proxy, bastion, and per-tool runners

# Bastion (public subnet, jump host)
resource "aws_instance" "bastion" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  key_name               = var.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.bastion.id]

  tags = { Name = "harness-bastion" }
}

# Honeypot + capture (private subnet)
resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type_honeypot
  key_name               = var.key_name
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  private_ip             = "10.0.2.10"

  user_data = templatefile("${path.module}/userdata/honeypot.sh", {
    honeypot_port = 8443
  })

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = { Name = "harness-honeypot" }
}

# Squid proxy (public subnet, domain-filtered LLM API access)
resource "aws_instance" "proxy" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  key_name               = var.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.proxy.id]
  private_ip             = "10.0.1.50"

  user_data = templatefile("${path.module}/userdata/proxy.sh", {
    allowed_domains = distinct(flatten([
      for tool in var.deploy_tools : tool.llm_api_domains
    ]))
  })

  tags = { Name = "harness-proxy" }
}

# Per-tool instances (private subnet)
resource "aws_instance" "tool" {
  for_each = var.deploy_tools

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type_tool
  key_name               = var.key_name
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.tool.id]

  user_data = templatefile("${path.module}/userdata/tool-runner.sh", {
    tool_name    = each.key
    docker_image = each.value.docker_image
    scan_command = replace(each.value.scan_command, "HONEYPOT_IP", "10.0.2.10")
    proxy_host   = "10.0.1.50"
    proxy_port   = 3128
    api_key = lookup({
      "openai_api_key"    = var.openai_api_key,
      "anthropic_api_key" = var.anthropic_api_key,
      "mistral_api_key"   = var.mistral_api_key,
    }, each.value.api_key_var, "")
    api_key_env_var = upper(each.value.api_key_var)
  })

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  tags = { Name = "harness-tool-${each.key}" }
}
