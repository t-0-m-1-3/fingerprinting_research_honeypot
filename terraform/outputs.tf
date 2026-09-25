output "bastion_public_ip" {
  description = "Bastion public IP for SSH access"
  value       = aws_instance.bastion.public_ip
}

output "honeypot_private_ip" {
  description = "Honeypot private IP"
  value       = aws_instance.honeypot.private_ip
}

output "proxy_private_ip" {
  description = "Squid proxy private IP"
  value       = aws_instance.proxy.private_ip
}

output "tool_private_ips" {
  description = "Per-tool instance private IPs"
  value       = { for k, v in aws_instance.tool : k => v.private_ip }
}

output "ssh_bastion" {
  description = "SSH command for bastion"
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${aws_instance.bastion.public_ip}"
}

output "ssh_honeypot_via_bastion" {
  description = "SSH to honeypot through bastion"
  value       = "ssh -J ubuntu@${aws_instance.bastion.public_ip} ubuntu@${aws_instance.honeypot.private_ip}"
}

output "flowlog_bucket" {
  description = "S3 bucket for VPC flow logs"
  value       = aws_s3_bucket.flowlogs.id
}

output "nat_gateway_ip" {
  description = "NAT gateway public IP (outbound IP for all tool traffic)"
  value       = aws_eip.nat.public_ip
}
