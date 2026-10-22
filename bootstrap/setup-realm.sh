#!/usr/bin/env bash
#
# setup-realm.sh — build the vulnerable "app" realm for the composite map-role lab.
#
# Creates everything report.md assumes already exists:
#   - realm `app`
#   - users: limited-admin (manage-users only), alice, bob, carol, dave
#   - clients: spa (non-admin OIDC), confidential (secret=confsecret)
#   - composite payloads: sneaky-composite -> realm-admin,
#                         outer-sneaky -> sneaky-composite,
#                         spa/hidden-ra -> realm-admin
#   - group `helpdesk` with alice as an existing member
#
# Idempotent: safe to re-run. Runs against $BASE as $ADMIN_USER/$ADMIN_PASS.
#
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
REALM="${REALM:-app}"
ADMIN_REALM="${ADMIN_REALM:-master}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
CLIENT_ID="${CLIENT_ID:-admin-cli}"

info() { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }

API="$BASE/admin/realms/$REALM"

tok() {
  curl -s -X POST "$BASE/realms/$ADMIN_REALM/protocol/openid-connect/token" \
    -d client_id="$CLIENT_ID" -d grant_type=password \
    -d username="$ADMIN_USER" -d password="$ADMIN_PASS" | jq -r '.access_token // empty'
}

# POST that tolerates 409 (already exists)
post() { # url json
  curl -s -o /dev/null -w '%{http_code}' -X POST "$1" \
    -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d "$2"
}
put() { # url
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$1" -H "Authorization: Bearer $AT"
}
get() { curl -s -H "Authorization: Bearer $AT" "$1"; }

info "Waiting for admin token at $BASE ..."
AT=""
for i in $(seq 1 60); do
  AT="$(tok)" || true
  [ -n "$AT" ] && break
  sleep 2
done
[ -n "$AT" ] || { echo "[-] could not obtain admin token"; exit 1; }
ok "admin token acquired"

# ---- realm ----
info "Creating realm '$REALM'"
post "$BASE/admin/realms" "{\"realm\":\"$REALM\",\"enabled\":true}" >/dev/null || true
ok "realm ready"

refresh_at() { AT="$(tok)"; }

# ---- users ----
create_user() { # username password email first last
  local u="$1" p="$2" e="$3" f="$4" l="$5"
  post "$API/users" "{\"username\":\"$u\",\"enabled\":true,\"email\":\"$e\",\"emailVerified\":true,\"firstName\":\"$f\",\"lastName\":\"$l\",\"credentials\":[{\"type\":\"password\",\"value\":\"$p\",\"temporary\":false}]}" >/dev/null || true
  local id; id="$(get "$API/users?username=$u&exact=true" | jq -r '.[0].id // empty')"
  # ensure password set even if user pre-existed
  [ -n "$id" ] && curl -s -o /dev/null -X PUT "$API/users/$id/reset-password" \
    -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
    -d "{\"type\":\"password\",\"value\":\"$p\",\"temporary\":false}" || true
  printf '%s' "$id"
}

info "Creating users"
LA="$(create_user limited-admin limitedpass limited@example.com Limited Admin)"
ALICE="$(create_user alice alicepass alice@example.com Alice A)"
BOB="$(create_user bob bobpass bob@example.com Bob B)"
CAROL="$(create_user carol carolpass carol@example.com Carol C)"
DAVE="$(create_user dave davepass dave@example.com Dave D)"
ok "users: limited-admin=$LA alice=$ALICE bob=$BOB carol=$CAROL"

# ---- grant manage-users (only) to limited-admin ----
info "Granting realm-management/manage-users to limited-admin"
RM="$(get "$API/clients?clientId=realm-management" | jq -r '.[0].id')"
MU="$(get "$API/clients/$RM/roles/manage-users")"
MU_ID="$(printf '%s' "$MU" | jq -r '.id')"
post "$API/users/$LA/role-mappings/clients/$RM" "[{\"id\":\"$MU_ID\",\"name\":\"manage-users\"}]" >/dev/null
ok "limited-admin now holds manage-users (and nothing else)"

# ---- clients ----
info "Creating client 'spa' (non-admin OIDC)"
post "$API/clients" '{"clientId":"spa","protocol":"openid-connect","publicClient":true,"standardFlowEnabled":true,"enabled":true}' >/dev/null || true
SPA="$(get "$API/clients?clientId=spa" | jq -r '.[0].id')"

info "Creating client 'confidential' (secret=confsecret)"
post "$API/clients" '{"clientId":"confidential","protocol":"openid-connect","publicClient":false,"secret":"confsecret","serviceAccountsEnabled":true,"standardFlowEnabled":true,"enabled":true}' >/dev/null || true
CONF="$(get "$API/clients?clientId=confidential" | jq -r '.[0].id')"
# force the secret value deterministically
[ -n "$CONF" ] && curl -s -o /dev/null -X PUT "$API/clients/$CONF" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"clientId":"confidential","secret":"confsecret","publicClient":false,"serviceAccountsEnabled":true}' || true
ok "clients: spa=$SPA confidential=$CONF"

# ---- composite payloads ----
RA="$(get "$API/clients/$RM/roles/realm-admin" | jq -r '.id')"
ok "realm-admin role id: $RA"

info "Payload 1: realm role 'sneaky-composite' -> realm-admin"
post "$API/roles" '{"name":"sneaky-composite","description":"hides realm-admin"}' >/dev/null || true
SNEAKY="$(get "$API/roles/sneaky-composite" | jq -r '.id')"
post "$API/roles-by-id/$SNEAKY/composites" "[{\"id\":\"$RA\",\"name\":\"realm-admin\"}]" >/dev/null

info "Payload 2: realm role 'outer-sneaky' -> sneaky-composite"
post "$API/roles" '{"name":"outer-sneaky","description":"wraps sneaky-composite"}' >/dev/null || true
OUTER="$(get "$API/roles/outer-sneaky" | jq -r '.id')"
post "$API/roles-by-id/$OUTER/composites" "[{\"id\":\"$SNEAKY\",\"name\":\"sneaky-composite\"}]" >/dev/null

info "Payload 3: client role 'spa/hidden-ra' -> realm-admin"
post "$API/clients/$SPA/roles" '{"name":"hidden-ra","description":"client-role wrapper of realm-admin"}' >/dev/null || true
HID="$(get "$API/clients/$SPA/roles/hidden-ra" | jq -r '.id')"
post "$API/roles-by-id/$HID/composites" "[{\"id\":\"$RA\",\"name\":\"realm-admin\"}]" >/dev/null
ok "composite payloads planted (sneaky=$SNEAKY outer=$OUTER hidden-ra=$HID)"

# ---- group with existing member ----
info "Creating group 'helpdesk' with alice as member"
post "$API/groups" '{"name":"helpdesk"}' >/dev/null || true
HELP="$(get "$API/groups?search=helpdesk" | jq -r '.[]|select(.name=="helpdesk")|.id' | head -n1)"
[ -n "$HELP" ] && [ -n "$ALICE" ] && put "$API/users/$ALICE/groups/$HELP" >/dev/null
ok "group helpdesk=$HELP (alice is a member)"

echo
ok "=========================================================="
ok " Lab realm '$REALM' is ready."
ok " Attacker : limited-admin / limitedpass   (manage-users only)"
ok " Victims  : alice/alicepass bob/bobpass carol/carolpass"
ok " Run the PoC:  ./poc/kc_composite_maprole_poc.sh check"
ok "=========================================================="
