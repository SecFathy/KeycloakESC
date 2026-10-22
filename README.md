# Keycloak composite map-role privilege escalation — reproducible lab

A self-contained Docker lab that reproduces a privilege-escalation path in Keycloak's
admin REST API: a delegated admin who holds **only `manage-users`** can map a
**composite role whose name is ordinary but whose children include
`realm-management/realm-admin`**, escalating itself (or any user/group) to full
realm-admin.

This is a variant of the hardening done for **CVE-2026-94000**. That fix added a
recursive admin-role walk to **group join** (`GroupUtils.checkAdminGroupRoles`), but
the same walk is missing from the role-mapping endpoints:

- `RoleMapperResource.addRealmRoleMappings` (users **and** groups)
- `ClientRoleMappingsResource.addClientRoleMapping`

`RolePermissionsV2.canMapRole` treats a role as privileged only when its container is
`realm-management`/`master` **and** its name is in `AdminRoles.ALL_ROLES`. A composite
named `sneaky-composite` that wraps `realm-admin` passes that gate.

Full technical write-up, root cause, and remediation: [`report/report.md`](report/report.md).
Confirmed end-to-end run against `quay.io/keycloak/keycloak:26.8.1`: [`VALIDATION.md`](VALIDATION.md).

> **Authorized research only.** Everything here runs against a throwaway Keycloak on
> `localhost`. Do not point the PoC at systems you are not explicitly authorized to test.

---

## Requirements

- Docker + Docker Compose v2
- `curl` and `jq` on the host (for the PoC script)

## Quick start

```bash
cp .env.example .env            # optional: pin KC_VERSION
make up                         # start Keycloak 26.8.1 + auto-bootstrap the lab realm
make logs                       # watch until "Lab realm 'app' is ready"

make check                      # non-destructive detection (maps + immediately unmaps)
make exploit                    # Attack A: self-escalate limited-admin -> realm-admin
make all                        # full chain: check + A + B + C + D
make clean                      # tear everything down
```

The `bootstrap` container waits for Keycloak to become healthy, then builds the realm
described below and exits.

## What the lab contains (realm `app`)

| Object | Purpose |
|---|---|
| `limited-admin` / `limitedpass` | Attacker — holds **only** `manage-users` |
| `alice` / `bob` / `carol` / `dave` | Victim users |
| `sneaky-composite` (realm role) | Composite → `realm-management/realm-admin` |
| `outer-sneaky` (realm role) | Composite → `sneaky-composite` (one extra hop) |
| `spa` client + `spa/hidden-ra` | Non-admin client role → `realm-admin` |
| `confidential` client (`confsecret`) | Secret-read impact target |
| `helpdesk` group (alice is a member) | Group-mapping attack target |

## Attacks demonstrated by the PoC

| Mode | Scenario | Expected |
|---|---|---|
| `check` | Probe: map wrapper onto self, roll back | VULNERABLE (204) |
| `exploit` / `attack-a` | Self-map `sneaky-composite` → realm-admin | 204 → full admin |
| `attack-b` | Nested `outer-sneaky` onto bob (depth not checked) | 204 → admin |
| `attack-c` | `spa/hidden-ra` client role onto carol | 204 → admin |
| `attack-d` | Map wrapper onto `helpdesk` (existing member alice) | 204 → admin; new **join** still 403 |

## Validating a fix

Point the lab at a patched build and re-run — a fixed server must return **403** on
every `map` step while still allowing ordinary non-admin role mapping:

```bash
KC_VERSION=<patched-tag> docker compose up -d --force-recreate
make check          # expect: NOT vulnerable
```

## Layout

```
docker-compose.yml        Keycloak + one-shot bootstrap container
bootstrap/setup-realm.sh  Builds the vulnerable realm via the admin REST API
poc/kc_composite_maprole_poc.sh  Detection + exploitation PoC (curl/jq)
report/report.md          Full technical write-up
```

## Remediation (summary)

Apply the recursive admin-role walk from `GroupUtils.requireMapRoleRecursive` to
`RolePermissionsV2.canMapRole` / `RolePermissions.checkAdminRoles`, and run it for
`RoleMapperResource` (users **and** groups) and `ClientRoleMappingsResource`. Reject a
role when `AdminRoles.isAdminRoleOrComposite(role)` is true unless the caller may map
**every** nested admin role. See the report for test coverage that the group-join test
alone does not provide.

## License

MIT — see [`LICENSE`](LICENSE).
