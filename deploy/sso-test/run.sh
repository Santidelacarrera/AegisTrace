#!/usr/bin/env bash
# Starts Dex (a real OIDC IdP) on :5556. Then run the API with:
#   OIDC_ISSUER=http://127.0.0.1:5556/dex OIDC_CLIENT_ID=aegis OIDC_CLIENT_SECRET=aegis-test-secret \
#   OIDC_REDIRECT_URI=http://localhost:3000/api/v1/auth/oidc/callback OIDC_ORG_ID=org-acme \
#   OIDC_GROUPS_CLAIM=email OIDC_ROLE_MAP='{"admin@example.com":"admin"}' npm run dev   (in api/)
# and drive it with: node web/e2e/sso.mjs   (Dex's static users carry no groups, so the e-mail claim stands in for a group)
set -euo pipefail
docker rm -f aegis-dex >/dev/null 2>&1 || true
docker run -d --name aegis-dex --network host -v "$(cd "$(dirname "$0")" && pwd)/dex.yaml:/etc/dex/config.yaml:ro" \
  "${DEX_IMAGE:-dexidp/dex:v2.41.1}" dex serve /etc/dex/config.yaml
