# Keycloak composite map-role privilege escalation

A reproducible Docker lab and PoC for a privilege-escalation path in Keycloak's admin
REST API: a delegated admin holding **only `manage-users`** can escalate itself (or any
user or group) to full **`realm-admin`** by mapping a composite role whose *name* is
ordinary but whose *children* include `realm-management/realm-admin`.

Confirmed end-to-end against the official image `quay.io/keycloak/keycloak:26.8.1`.

> ⚠️ **Authorized research only.** Everything runs against a throwaway Keycloak on
> `localhost`. Do not point the PoC at systems you are not explicitly authorized to test.

- [The issue (root cause)](#the-issue-root-cause)
- [Proof of concept](#proof-of-concept)
- [Verified run](#verified-run)
- [Remediation](#remediation)

---

## The issue (root cause)

Keycloak **26.8.1** hardened **group join** (CVE-2026-94000): a `manage-users` admin can
no longer add a user to a group that transitively grants `realm-management` admin roles.
`GroupUtils.checkAdminGroupRoles` walks the group's roles **recursively** and calls
`requireMapRole` on every nested admin role:

```java
private static void requireMapRoleRecursive(RoleModel role, AdminPermissionEvaluator auth, Set<String> visited) {
    if (!visited.add(role.getId())) return;
    if (AdminRoles.isAdminRole(role)) auth.roles().requireMapRole(role);   // checks nested admin roles
    if (role.isComposite()) role.getCompositesStream().forEach(child -> requireMapRoleRecursive(child, auth, visited));
}
```

**The same recursive walk was never added to the role-mapping endpoints.** When a role is
mapped directly onto a user or group, the server only checks the **posted** role:

```java
// RoleMapperResource.addRealmRoleMappings — mounted on BOTH users and groups
for (RoleRepresentation role : roles) {
    RoleModel roleModel = realm.getRole(role.getName());
    auth.roles().requireMapRole(roleModel);   // posted role only — children never inspected
    roleMapper.grantRole(roleModel);
}
```

And the privilege gate itself keys on the role's **name**, not its contents. In
`RolePermissionsV2.canMapRole`, a role counts as privileged only when its container is
`realm-management`/`master` **and** its name is in `AdminRoles.ALL_ROLES`:

```java
public boolean canMapRole(RoleModel role) {
    if (isRealmAdminRole(role)) { ... }                 // isRealmAdminRole = container + ALL_ROLES.contains(name)
    if (root.hasOneAdminRole(AdminRoles.MANAGE_USERS))  // manage-users may map ANY non-admin-named role
        return true;
    ...
}
```

So a composite named `sneaky-composite` that wraps `realm-management/realm-admin` passes
the gate — its name is not in `ALL_ROLES`, and its children are never walked. The gap
spans three endpoints:

- `RoleMapperResource.addRealmRoleMappings` — **users and groups**
- `ClientRoleMappingsResource.addClientRoleMapping` — **client roles on any client**

**Net effect:** the privileged payload (a composite wrapping `realm-admin`) only needs to
*exist* — created by a real admin, a realm import, or an earlier process. `manage-users`
can then **assign** it, which the CVE-2026-94000 threat model never intended.

### Attack variants

| # | Variant | Why it works |
|---|---|---|
| **A** | Self-map `sneaky-composite` → `realm-admin` | name gate misses the composite |
| **B** | Map nested `outer-sneaky` (`→ sneaky-composite → realm-admin`) onto a user | depth is not checked |
| **C** | Map a client role on a non-admin client (`spa/hidden-ra → realm-admin`) | `ClientRoleMappingsResource` uses the same gate |
| **D** | Map the composite **onto a group** that already has members | different API than join; existing members escalate without any join |

---

## Proof of concept

**Requirements:** Docker + Docker Compose v2, and `curl` + `jq` on the host.

```bash
cp .env.example .env     # optional: pin KC_VERSION (default 26.8.1)
make up                  # start Keycloak + auto-bootstrap the vulnerable realm `app`
make logs                # wait for "Lab realm 'app' is ready"

make check               # non-destructive detection (maps, then immediately unmaps)
make exploit             # Attack A: self-escalate limited-admin -> realm-admin
make all                 # full chain: check + A + B + C + D
make reset               # undo every escalation (keep the lab running)
make clean               # tear everything down
```

The one-shot `bootstrap` container builds the scenario via the admin REST API, then exits:

| Object | Purpose |
|---|---|
| `limited-admin` / `limitedpass` | **Attacker** — holds only `manage-users` |
| `alice` / `bob` / `carol` / `dave` | Victim users |
| `sneaky-composite` (realm role) | Composite → `realm-management/realm-admin` |
| `outer-sneaky` (realm role) | Composite → `sneaky-composite` (one extra hop) |
| `spa` client + `spa/hidden-ra` role | Non-admin client role → `realm-admin` |
| `confidential` client (`confsecret`) | Secret-read impact target |
| `helpdesk` group (alice is a member) | Group-mapping attack target |

The PoC resolves role IDs the way a `manage-users` caller actually can — via the
`.../role-mappings/.../available` endpoints — because that account is denied
`GET /roles/{name}` and `GET /clients` (403) but **not** the available lists. This keeps
the script an honest low-privilege attacker's-eye reproduction.

### Validating a fix

Point the lab at a patched build; a fixed server must return **403** on every map step
while still allowing ordinary non-admin role mapping:

```bash
KC_VERSION=<patched-tag> docker compose up -d --force-recreate
make check        # expect: NOT vulnerable
```

---

## Verified run

Against `quay.io/keycloak/keycloak:26.8.1` (full transcript in [`docs/demo.txt`](docs/demo.txt),
details in [`VALIDATION.md`](VALIDATION.md)):

| Step | Action | Result |
|---|---|---|
| Baseline | `limited-admin` `POST /roles` | **403** (genuinely low-priv) |
| check | map `sneaky-composite` onto self (then unmap) | **204** → VULNERABLE |
| **A** | self-map `sneaky-composite` → realm-admin → create role / dump user emails | **204 / 201 / 200** |
| **B** | nested `outer-sneaky` onto bob → bob creates role | **204 / 201** |
| **C** | `spa/hidden-ra` onto carol → carol creates role | **204 / 201** |
| **D** | map wrapper onto `helpdesk` → existing member alice creates role | **204 / 201** |
| D control | `manage-users` **joins** a new member to `helpdesk` | **403** (CVE-2026-94000 fix intact) |

The D control proves the asymmetry: group **join** is blocked, but mapping the same
composite **onto** the group (or onto a user/client) is not walked and returns 204.

---

## Remediation

1. In `RolePermissionsV2.canMapRole` / `RolePermissions.checkAdminRoles`, reject a role
   when `AdminRoles.isAdminRoleOrComposite(role)` is true unless the caller may map
   **every** nested admin role — mirror `GroupUtils.requireMapRoleRecursive`.
2. Run that walk for `RoleMapperResource.addRealmRoleMappings` (**users and groups**) and
   `ClientRoleMappingsResource.addClientRoleMapping`.
3. Add test coverage that `manage-users` cannot map `sneaky-composite`, a nested wrapper,
   a non-admin client role that composites `realm-admin`, or the wrapper onto a group with
   members. The existing group-join test alone is not sufficient.

Full technical write-up: [`report/report.md`](report/report.md).

## Layout

```
docker-compose.yml               Keycloak + one-shot bootstrap container
bootstrap/setup-realm.sh         Builds the vulnerable realm via the admin REST API
poc/kc_composite_maprole_poc.sh  Detection + exploitation + cleanup PoC (curl/jq)
report/report.md                 Full technical write-up
VALIDATION.md / docs/demo.txt    Verified run evidence
```

## License

MIT — see [`LICENSE`](LICENSE).
