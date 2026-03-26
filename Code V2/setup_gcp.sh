#!/usr/bin/env bash
# ─── GCP Sentinel v2 — One-time GCP Infrastructure Setup ─────────────────────
# Sets up Pub/Sub, log sinks, firewall rules, IAM, and service account
# Usage: bash setup_gcp.sh YOUR_PROJECT_ID your-company-domain.com
#
# Requirements:
#   - gcloud CLI installed (cloud.google.com/sdk)
#   - gcloud auth login already run
#   - Owner or Editor role on the GCP project

set -e

# ─── Args ─────────────────────────────────────────────────────────────────────
PROJECT=${1:-"your-project-id"}
COMPANY_DOMAIN=${2:-"yourcompany.com"}

# ─── Config ───────────────────────────────────────────────────────────────────
TOPIC="sentinel-alerts"
SUBSCRIPTION="sentinel-sub"
SA_NAME="gcp-sentinel-v2"
SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
FIREWALL_TAG="sentinel-monitored"
CREDENTIALS_FILE="gcp-credentials.json"
SINK_NAME="sentinel-audit-sink"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       GCP Sentinel v2 — Infrastructure Setup     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Project:        ${GREEN}$PROJECT${NC}"
echo -e "  Company domain: ${GREEN}@$COMPANY_DOMAIN${NC}"
echo -e "  Service account:${GREEN}$SA_EMAIL${NC}"
echo ""
read -p "  Proceed? (y/n): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi
echo ""

# ─── 0. Set project ───────────────────────────────────────────────────────────
echo -e "${CYAN}[0/8]${NC} Setting active project..."
gcloud config set project "$PROJECT" --quiet
echo -e "  ${GREEN}✓${NC} Project set to $PROJECT"

# ─── 1. Enable APIs ───────────────────────────────────────────────────────────
echo -e "${CYAN}[1/8]${NC} Enabling required GCP APIs..."
gcloud services enable \
  pubsub.googleapis.com \
  logging.googleapis.com \
  compute.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  --quiet
echo -e "  ${GREEN}✓${NC} APIs enabled"

# ─── 2. Pub/Sub topic + subscription ─────────────────────────────────────────
echo -e "${CYAN}[2/8]${NC} Creating Pub/Sub topic and subscription..."
gcloud pubsub topics create "$TOPIC" --quiet 2>/dev/null \
  && echo -e "  ${GREEN}✓${NC} Topic created: $TOPIC" \
  || echo -e "  ${YELLOW}⚠${NC}  Topic already exists: $TOPIC"

gcloud pubsub subscriptions create "$SUBSCRIPTION" \
  --topic="$TOPIC" \
  --ack-deadline=60 \
  --message-retention-duration=7d \
  --quiet 2>/dev/null \
  && echo -e "  ${GREEN}✓${NC} Subscription created: $SUBSCRIPTION" \
  || echo -e "  ${YELLOW}⚠${NC}  Subscription already exists: $SUBSCRIPTION"

# ─── 3. Cloud Audit Log sink ──────────────────────────────────────────────────
echo -e "${CYAN}[3/8]${NC} Creating Cloud Audit Log sink..."

LOG_FILTER='protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
AND (
  protoPayload.authenticationInfo.principalEmail!~"@'"$COMPANY_DOMAIN"'"
  OR protoPayload.authenticationInfo.principalEmail=""
  OR protoPayload.authenticationInfo.principalEmail=~"iam.gserviceaccount.com$"
)
AND severity >= WARNING'

gcloud logging sinks create "$SINK_NAME" \
  "pubsub.googleapis.com/projects/${PROJECT}/topics/${TOPIC}" \
  --log-filter="$LOG_FILTER" \
  --quiet 2>/dev/null \
  && echo -e "  ${GREEN}✓${NC} Log sink created: $SINK_NAME" \
  || echo -e "  ${YELLOW}⚠${NC}  Log sink already exists (updating filter)..."

# Update filter if sink already existed
gcloud logging sinks update "$SINK_NAME" \
  --log-filter="$LOG_FILTER" \
  --quiet 2>/dev/null || true

# ─── 4. Grant Pub/Sub publisher to log sink SA ────────────────────────────────
echo -e "${CYAN}[4/8]${NC} Granting Pub/Sub publisher role to log sink..."
SINK_SA=$(gcloud logging sinks describe "$SINK_NAME" --format='value(writerIdentity)')
gcloud pubsub topics add-iam-policy-binding "$TOPIC" \
  --member="$SINK_SA" \
  --role="roles/pubsub.publisher" \
  --quiet
echo -e "  ${GREEN}✓${NC} Publisher role granted to: $SINK_SA"

# ─── 5. Service account ───────────────────────────────────────────────────────
echo -e "${CYAN}[5/8]${NC} Creating service account for GCP Sentinel..."
gcloud iam service-accounts create "$SA_NAME" \
  --display-name="GCP Sentinel v2 Security Bot" \
  --description="Auto-response security account for GCP Sentinel v2" \
  --quiet 2>/dev/null \
  && echo -e "  ${GREEN}✓${NC} Service account created: $SA_EMAIL" \
  || echo -e "  ${YELLOW}⚠${NC}  Service account already exists"

# ─── 6. IAM roles ─────────────────────────────────────────────────────────────
echo -e "${CYAN}[6/8]${NC} Assigning IAM roles to service account..."
ROLES=(
  "roles/logging.viewer"
  "roles/pubsub.subscriber"
  "roles/pubsub.viewer"
  "roles/compute.instanceAdmin.v1"
  "roles/compute.securityAdmin"
  "roles/iam.securityReviewer"
  "roles/iam.roleViewer"
)

for ROLE in "${ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="$ROLE" \
    --quiet
  echo -e "  ${GREEN}✓${NC} Granted: $ROLE"
done

# ─── 7. Default deny firewall rule for sentinel blocks ────────────────────────
echo -e "${CYAN}[7/8]${NC} Creating base firewall rule for sentinel blocks..."
gcloud compute firewall-rules create "sentinel-auto-block-base" \
  --direction=INGRESS \
  --priority=900 \
  --action=DENY \
  --rules=all \
  --source-ranges="240.0.0.0/4" \
  --description="Base rule managed by GCP Sentinel v2 auto-block" \
  --quiet 2>/dev/null \
  && echo -e "  ${GREEN}✓${NC} Base firewall rule created" \
  || echo -e "  ${YELLOW}⚠${NC}  Base firewall rule already exists"

# ─── 8. Download credentials ──────────────────────────────────────────────────
echo -e "${CYAN}[8/8]${NC} Downloading service account credentials..."
if [ -f "$CREDENTIALS_FILE" ]; then
  echo -e "  ${YELLOW}⚠${NC}  $CREDENTIALS_FILE already exists — creating new key anyway"
fi
gcloud iam service-accounts keys create "$CREDENTIALS_FILE" \
  --iam-account="$SA_EMAIL" \
  --quiet
echo -e "  ${GREEN}✓${NC} Credentials saved to: $CREDENTIALS_FILE"

# ─── .gitignore ───────────────────────────────────────────────────────────────
if [ ! -f ".gitignore" ]; then
  cat > .gitignore << EOF
# GCP Sentinel — secrets
.env
gcp-credentials.json
*.json
__pycache__/
*.pyc
EOF
  echo -e "  ${GREEN}✓${NC} .gitignore created"
fi

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           ✅  Setup Complete!                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Next steps:"
echo ""
echo -e "  ${CYAN}1.${NC} Edit your .env file and set:"
echo -e "     ${YELLOW}GCP_PROJECT_ID=${PROJECT}${NC}"
echo -e "     ${YELLOW}GCP_CREDENTIALS_FILE=./${CREDENTIALS_FILE}${NC}"
echo -e "     ${YELLOW}KNOWN_DOMAINS=@${COMPANY_DOMAIN}${NC}"
echo ""
echo -e "  ${CYAN}2.${NC} Install GCP Python packages:"
echo -e "     ${YELLOW}py -m pip install google-cloud-compute google-cloud-pubsub google-cloud-logging google-auth${NC}"
echo ""
echo -e "  ${CYAN}3.${NC} Start GCP Sentinel:"
echo -e "     ${YELLOW}py app.py${NC}"
echo ""
echo -e "  ${RED}⚠  SECURITY REMINDERS:${NC}"
echo -e "     - Never commit ${YELLOW}${CREDENTIALS_FILE}${NC} or ${YELLOW}.env${NC} to Git"
echo -e "     - Rotate service account keys every 90 days"
echo -e "     - Update KNOWN_DOMAINS in .env to match your real domain"
echo ""
