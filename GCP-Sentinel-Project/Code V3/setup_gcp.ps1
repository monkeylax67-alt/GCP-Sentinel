# ─── GCP Sentinel v2 — Windows PowerShell Setup Script ──────────────────────
# Sets up Pub/Sub, log sinks, firewall rules, IAM, and service account
# Usage: .\setup_gcp.ps1 -Project YOUR_PROJECT_ID -Domain yourcompany.com
#
# Requirements:
#   - gcloud CLI installed (cloud.google.com/sdk)
#   - Run 'gcloud auth login' first
#   - Owner or Editor role on the GCP project

param(
    [Parameter(Mandatory=$true)]
    [string]$Project,

    [Parameter(Mandatory=$false)]
    [string]$Domain = "yourcompany.com"
)

# ─── Config ───────────────────────────────────────────────────────────────────
$TOPIC          = "sentinel-alerts"
$SUBSCRIPTION   = "sentinel-sub"
$SA_NAME        = "gcp-sentinel-v2"
$SA_EMAIL       = "${SA_NAME}@${Project}.iam.gserviceaccount.com"
$SINK_NAME      = "sentinel-audit-sink"
$CREDENTIALS    = "gcp-credentials.json"

# ─── Helpers ──────────────────────────────────────────────────────────────────
function Write-Step($n, $msg) {
    Write-Host ""
    Write-Host "  [$n/8] $msg" -ForegroundColor Cyan
}
function Write-OK($msg)   { Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  WARN  $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "  FAIL  $msg" -ForegroundColor Red }

# ─── Banner ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  =================================================" -ForegroundColor Cyan
Write-Host "    GCP Sentinel v2 -- Infrastructure Setup" -ForegroundColor Cyan
Write-Host "  =================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Project:         $Project" -ForegroundColor White
Write-Host "  Company domain:  @$Domain" -ForegroundColor White
Write-Host "  Service account: $SA_EMAIL" -ForegroundColor White
Write-Host ""
$confirm = Read-Host "  Proceed? (y/n)"
if ($confirm -ne "y" -and $confirm -ne "Y") {
    Write-Host "  Aborted." -ForegroundColor Yellow
    exit 0
}

# ─── Check gcloud is installed ────────────────────────────────────────────────
Write-Host ""
Write-Host "  Checking gcloud CLI..." -ForegroundColor Cyan
try {
    $null = gcloud version 2>&1
    Write-OK "gcloud CLI found"
} catch {
    Write-Fail "gcloud CLI not found. Install it from: https://cloud.google.com/sdk"
    Write-Host "  Then run: gcloud auth login" -ForegroundColor Yellow
    exit 1
}

# ─── 0. Set project ───────────────────────────────────────────────────────────
Write-Step "0" "Setting active project..."
gcloud config set project $Project --quiet
if ($LASTEXITCODE -eq 0) { Write-OK "Project set to $Project" }
else { Write-Fail "Could not set project. Check the project ID."; exit 1 }

# ─── 1. Enable APIs ───────────────────────────────────────────────────────────
Write-Step "1" "Enabling required GCP APIs (this may take 1-2 minutes)..."
$apis = @(
    "pubsub.googleapis.com",
    "logging.googleapis.com",
    "compute.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com"
)
foreach ($api in $apis) {
    gcloud services enable $api --quiet 2>$null
    Write-OK "Enabled: $api"
}

# ─── 2. Pub/Sub topic + subscription ─────────────────────────────────────────
Write-Step "2" "Creating Pub/Sub topic and subscription..."

gcloud pubsub topics create $TOPIC --quiet 2>$null
if ($LASTEXITCODE -eq 0) { Write-OK "Topic created: $TOPIC" }
else { Write-Warn "Topic already exists: $TOPIC" }

gcloud pubsub subscriptions create $SUBSCRIPTION `
    --topic=$TOPIC `
    --ack-deadline=60 `
    --message-retention-duration=7d `
    --quiet 2>$null
if ($LASTEXITCODE -eq 0) { Write-OK "Subscription created: $SUBSCRIPTION" }
else { Write-Warn "Subscription already exists: $SUBSCRIPTION" }

# ─── 3. Cloud Audit Log sink ──────────────────────────────────────────────────
Write-Step "3" "Creating Cloud Audit Log sink..."

$logFilter = @"
protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
AND (
  protoPayload.authenticationInfo.principalEmail!~"@$Domain"
  OR protoPayload.authenticationInfo.principalEmail=""
  OR protoPayload.authenticationInfo.principalEmail=~"iam.gserviceaccount.com$"
)
AND severity >= WARNING
"@

gcloud logging sinks create $SINK_NAME `
    "pubsub.googleapis.com/projects/${Project}/topics/${TOPIC}" `
    --log-filter="$logFilter" `
    --quiet 2>$null
if ($LASTEXITCODE -eq 0) { Write-OK "Log sink created: $SINK_NAME" }
else {
    Write-Warn "Log sink already exists — updating filter..."
    gcloud logging sinks update $SINK_NAME --log-filter="$logFilter" --quiet 2>$null
    Write-OK "Log sink filter updated"
}

# ─── 4. Grant Pub/Sub publisher to log sink SA ────────────────────────────────
Write-Step "4" "Granting Pub/Sub publisher role to log sink..."
$SINK_SA = gcloud logging sinks describe $SINK_NAME --format="value(writerIdentity)"
gcloud pubsub topics add-iam-policy-binding $TOPIC `
    --member="$SINK_SA" `
    --role="roles/pubsub.publisher" `
    --quiet
Write-OK "Publisher role granted to: $SINK_SA"

# ─── 5. Service account ───────────────────────────────────────────────────────
Write-Step "5" "Creating service account..."
gcloud iam service-accounts create $SA_NAME `
    --display-name="GCP Sentinel v2 Security Bot" `
    --description="Auto-response security account for GCP Sentinel v2" `
    --quiet 2>$null
if ($LASTEXITCODE -eq 0) { Write-OK "Service account created: $SA_EMAIL" }
else { Write-Warn "Service account already exists" }

# ─── 6. IAM roles ─────────────────────────────────────────────────────────────
Write-Step "6" "Assigning IAM roles..."
$roles = @(
    "roles/logging.viewer",
    "roles/pubsub.subscriber",
    "roles/pubsub.viewer",
    "roles/compute.instanceAdmin.v1",
    "roles/compute.securityAdmin",
    "roles/iam.securityReviewer",
    "roles/iam.roleViewer"
)
foreach ($role in $roles) {
    gcloud projects add-iam-policy-binding $Project `
        --member="serviceAccount:$SA_EMAIL" `
        --role="$role" `
        --quiet 2>$null
    Write-OK "Granted: $role"
}

# ─── 7. Base firewall rule ────────────────────────────────────────────────────
Write-Step "7" "Creating base firewall rule for sentinel auto-blocks..."
gcloud compute firewall-rules create "sentinel-auto-block-base" `
    --direction=INGRESS `
    --priority=900 `
    --action=DENY `
    --rules=all `
    --source-ranges="240.0.0.0/4" `
    --description="Base rule managed by GCP Sentinel v2 auto-block" `
    --quiet 2>$null
if ($LASTEXITCODE -eq 0) { Write-OK "Base firewall rule created" }
else { Write-Warn "Base firewall rule already exists" }

# ─── 8. Download credentials ──────────────────────────────────────────────────
Write-Step "8" "Downloading service account credentials..."
if (Test-Path $CREDENTIALS) {
    Write-Warn "$CREDENTIALS already exists — creating new key"
}
gcloud iam service-accounts keys create $CREDENTIALS `
    --iam-account="$SA_EMAIL" `
    --quiet
Write-OK "Credentials saved to: $CREDENTIALS"

# ─── .gitignore ───────────────────────────────────────────────────────────────
if (-not (Test-Path ".gitignore")) {
    @"
# GCP Sentinel v2 -- secrets
.env
gcp-credentials.json
*.json
__pycache__/
*.pyc
"@ | Out-File -FilePath ".gitignore" -Encoding utf8
    Write-OK ".gitignore created"
}

# ─── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  =================================================" -ForegroundColor Green
Write-Host "    Setup Complete!" -ForegroundColor Green
Write-Host "  =================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host ""
Write-Host "  1. Edit your .env file and set:" -ForegroundColor Cyan
Write-Host "     GCP_PROJECT_ID=$Project" -ForegroundColor Yellow
Write-Host "     GCP_CREDENTIALS_FILE=./$CREDENTIALS" -ForegroundColor Yellow
Write-Host "     KNOWN_DOMAINS=@$Domain" -ForegroundColor Yellow
Write-Host ""
Write-Host "  2. Install GCP Python packages:" -ForegroundColor Cyan
Write-Host "     py -m pip install google-cloud-compute google-cloud-pubsub google-cloud-logging google-auth" -ForegroundColor Yellow
Write-Host ""
Write-Host "  3. Start GCP Sentinel:" -ForegroundColor Cyan
Write-Host "     py app.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "  SECURITY REMINDERS:" -ForegroundColor Red
Write-Host "   - Never commit $CREDENTIALS or .env to Git" -ForegroundColor White
Write-Host "   - Rotate service account keys every 90 days" -ForegroundColor White
Write-Host "   - Update KNOWN_DOMAINS in .env with your real domain" -ForegroundColor White
Write-Host ""
