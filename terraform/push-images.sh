#!/usr/bin/env bash
# Build tool Docker images locally and push to ECR.
#
# Prerequisites:
#   - Docker running locally
#   - AWS CLI configured with push access to ECR
#   - Terraform already applied (creates ECR repos)
#
# Usage:
#   cd terraform && ./push-images.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HARNESS_DIR="$PROJECT_ROOT/harness"

# Get ECR URLs from Terraform output
echo "Reading ECR repository URLs from Terraform state..."
ECR_REPOS=$(terraform output -json ecr_repositories 2>/dev/null)
if [ -z "$ECR_REPOS" ] || [ "$ECR_REPOS" = "{}" ]; then
    echo "ERROR: No ECR repositories found. Run 'terraform apply' first."
    exit 1
fi

# Get AWS region and account for ECR login
REGION=$(terraform output -raw bastion_public_ip 2>/dev/null | head -0; aws configure get region 2>/dev/null || echo "us-east-1")
REGION=$(cd "$SCRIPT_DIR" && terraform show -json 2>/dev/null | python3 -c "
import json, sys
state = json.load(sys.stdin)
for r in state.get('values', {}).get('root_module', {}).get('resources', []):
    if r['type'] == 'aws_ecr_repository':
        # Extract region from ARN: arn:aws:ecr:REGION:ACCOUNT:repository/name
        arn = r['values'].get('arn', '')
        print(arn.split(':')[3])
        break
" 2>/dev/null || echo "us-east-1")

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"

echo "ECR Registry: $ECR_REGISTRY"
echo "Region: $REGION"
echo ""

# Authenticate Docker to ECR
echo "Authenticating to ECR..."
aws ecr get-login-password --region "$REGION" | \
    docker login --username AWS --password-stdin "$ECR_REGISTRY"
echo ""

# Map tool names to Dockerfiles
declare -A DOCKERFILES=(
    [strix]="strix.Dockerfile"
    [rogue]="rogue.Dockerfile"
    [xalgorix]="xalgorix.Dockerfile"
)

# Build and push each tool
for tool in $(echo "$ECR_REPOS" | python3 -c "import json,sys; [print(k) for k in json.load(sys.stdin)]"); do
    DOCKERFILE="${DOCKERFILES[$tool]:-}"
    if [ -z "$DOCKERFILE" ]; then
        echo "SKIP: No Dockerfile mapping for '$tool'"
        continue
    fi

    DOCKERFILE_PATH="$HARNESS_DIR/tools/$DOCKERFILE"
    if [ ! -f "$DOCKERFILE_PATH" ]; then
        echo "SKIP: $DOCKERFILE_PATH not found"
        continue
    fi

    ECR_URL=$(echo "$ECR_REPOS" | python3 -c "import json,sys; print(json.load(sys.stdin)['$tool'])")
    LOCAL_TAG="harness-$tool:latest"
    REMOTE_TAG="$ECR_URL:latest"

    echo "Building $tool..."
    docker build -t "$LOCAL_TAG" -f "$DOCKERFILE_PATH" "$HARNESS_DIR"

    echo "Tagging $LOCAL_TAG -> $REMOTE_TAG"
    docker tag "$LOCAL_TAG" "$REMOTE_TAG"

    echo "Pushing $REMOTE_TAG..."
    docker push "$REMOTE_TAG"
    echo "  Done: $tool"
    echo ""
done

echo "All images pushed to ECR."
echo "You can now run: terraform apply (to launch tool instances that pull from ECR)"
