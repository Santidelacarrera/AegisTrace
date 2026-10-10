#!/usr/bin/env bash
# End-to-end demo against a running API (default http://localhost:3000) using synthetic data and demo keys.
# Run from the repository root.
set -euo pipefail
BASE="${BASE:-http://localhost:3000}/api/v1"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
call() { local key=$1 method=$2 path=$3 body=${4:-}; curl -sS -X "$method" -H "x-api-key: $key" -H 'content-type: application/json' ${body:+-d "$body"} "$BASE$path"; }
js() { node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s);console.log($1)})"; }

echo "1) Ingest synthetic events"
node -e "console.log(JSON.stringify(JSON.parse(require('fs').readFileSync('data/synthetic/events.json','utf8')).slice(0,500)))" > "$TMP"
curl -sS -X POST -H 'x-api-key: demo-ingestor' -H 'content-type: application/json' --data @"$TMP" "$BASE/events" | js '`   accepted=${j.accepted} new alerts=${j.newAlerts}`'
echo "2) Most severe incident"
INC=$(call demo-analyst GET '/incidents?limit=1' | js 'j.items[0].id'); echo "   $INC"
call demo-analyst POST "/incidents/$INC/status" '{"status":"triaging"}' >/dev/null
echo "3) Evidence-cited analysis"
ANA=$(call demo-analyst POST "/incidents/$INC/analysis")
echo "$ANA" | js '"   "+j.summary'; echo "$ANA" | js '"   gaps: "+j.gaps.join(" | ")'
REC=$(echo "$ANA" | js 'j.recommendations.find(r=>r.executable)?.id ?? ""')
echo "4) Propose action (pending approval)"
ACT=$(call demo-analyst POST "/incidents/$INC/actions" "{\"recommendationId\":\"$REC\"}")
echo "$ACT" | js '`   ${j.type} ${j.target}: ${j.status}`'; ID=$(echo "$ACT" | js 'j.id')
echo "5) Analyst cannot approve:  $(call demo-analyst POST "/actions/$ID/approve" | js 'j.error')"
echo "6) Approver approves:       $(call demo-approver POST "/actions/$ID/approve" | js 'j.result')"
echo "7) Audit chain:             $(call demo-auditor GET /audit/verify | js 'JSON.stringify(j)')"
