#!/bin/sh
# Wrapper for hackingBuddyGPT WebAPITesting mode.
# Generates a config JSON with the target URL, then launches wintermute.
set -e

TARGET_URL="${TARGET_URL:-https://172.30.0.2:8443}"
LLM_MODEL="${LLM_MODEL:-ollama_chat/llama3.1:8b}"
LLM_API_BASE="${LLM_API_BASE:-http://172.30.0.3:11434/v1}"
LLM_API_KEY="${LLM_API_KEY:-dummy}"
MAX_ROUNDS="${MAX_ROUNDS:-30}"

# LiteLLM's ollama_chat provider reads OLLAMA_API_BASE (not OLLAMA_HOST)
export OLLAMA_API_BASE="${OLLAMA_HOST:-http://172.30.0.3:11434}"
export OLLAMA_HOST="${OLLAMA_HOST:-http://172.30.0.3:11434}"

cat > /tmp/target_config.json <<EOF
{
  "host": "${TARGET_URL}",
  "name": "honeypot",
  "description": "Target web application for fingerprinting research",
  "token": "",
  "correct_endpoints": [],
  "query_params": {},
  "password_file": "",
  "csv_file": ""
}
EOF

exec wintermute WebAPITesting \
  --llm.model "$LLM_MODEL" \
  --llm.api_base "$LLM_API_BASE" \
  --llm.api_key "$LLM_API_KEY" \
  --llm.context_size 8192 \
  --config_path /tmp/target_config.json \
  --limits.max_rounds "$MAX_ROUNDS" \
  --limits.max_cost 0 \
  --max_turns 15
