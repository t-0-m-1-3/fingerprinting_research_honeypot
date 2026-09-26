variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "key_name" {
  description = "EC2 key pair name for SSH access"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH to bastion (your IP/32)"
  type        = string
}

variable "instance_type_honeypot" {
  description = "EC2 instance type for honeypot + capture"
  type        = string
  default     = "t3.medium"
}

variable "instance_type_tool" {
  description = "EC2 instance type for tool runners"
  type        = string
  default     = "t3.small"
}

# LLM API keys — passed as env vars to tool instances
# Set via terraform.tfvars or TF_VAR_ env vars, never commit values

variable "openai_api_key" {
  description = "OpenAI API key for tools that use GPT-4o"
  type        = string
  sensitive   = true
  default     = ""
}

variable "anthropic_api_key" {
  description = "Anthropic API key for tools that use Claude"
  type        = string
  sensitive   = true
  default     = ""
}

variable "mistral_api_key" {
  description = "Mistral API key"
  type        = string
  sensitive   = true
  default     = ""
}

# Tool selection — which cloud LLM tools to deploy

variable "deploy_tools" {
  description = "Map of tool names to deploy. Each entry creates an EC2 instance."
  type = map(object({
    llm_api_domains = list(string) # Domains allowed in proxy ACL
    api_key_var     = string       # Which variable holds the API key
    docker_image    = string       # Docker image to run
    scan_command    = string       # Command to run against honeypot
  }))
  default = {
    strix = {
      llm_api_domains = ["api.openai.com"]
      api_key_var     = "openai_api_key"
      docker_image    = "harness-strix:latest"
      scan_command    = "strix -t https://HONEYPOT_IP:8443 -m quick --max-turns 20 --max-budget 5"
    }
    rogue = {
      llm_api_domains = ["api.openai.com"]
      api_key_var     = "openai_api_key"
      docker_image    = "harness-rogue:latest"
      scan_command    = "python3 /opt/rogue/run.py -u https://HONEYPOT_IP:8443 -p 3 -i 5 -m o4-mini"
    }
    xalgorix = {
      llm_api_domains = ["api.anthropic.com"]
      api_key_var     = "anthropic_api_key"
      docker_image    = "harness-xalgorix:latest"
      scan_command    = "xalgorix -t https://HONEYPOT_IP:8443"
    }
  }
}
