# Validation run

Reproduced end-to-end against the official image **`quay.io/keycloak/keycloak:26.8.1`**
started by this repo's `docker-compose.yml`, attacker = `limited-admin` holding only
`realm-management/manage-users`.

## Attacker's real permission surface (confirmed)

`manage-users` is correctly denied the admin-read endpoints, yet can still enumerate
and map roles:

| Endpoint | Result |
|---|---|
| `POST /admin/realms/app/roles` | **403** (genuinely low-priv) |
| `GET /admin/realms/app/roles/{name}` | **403** |
| `GET /admin/realms/app/clients` | **403** |
| `GET /admin/realms/app/users/{id}/role-mappings/realm/available` | **200** (exposes role IDs) |
| `GET /admin/realms/app/groups` / `users` | **200** |

The PoC therefore resolves every role ID through the `.../available` endpoints — the
authentic low-privilege attacker view.

## Results (HTTP status)

| Step | Action | Result |
|---|---|---|
| Baseline | `limited-admin` `POST /roles` | **403** |
| check | map `sneaky-composite` onto self (then unmap) | **204** → VULNERABLE |
| **A** | self-map `sneaky-composite` → realm-admin | **204** |
| A impact | new token: `POST /roles` | **201** |
| A impact | `GET /users` emails | **200** (alice/bob/carol/dave/limited-admin) |
| **B** | map nested `outer-sneaky` onto bob | **204** → bob `POST /roles` **201** |
| **C** | map `spa/hidden-ra` (non-admin client role) onto carol | **204** → carol `POST /roles` **201** |
| **D** | map `sneaky-composite` onto `helpdesk` (alice already a member) | **204** → alice `POST /roles` **201** |
| D control | `manage-users` **joins** new member bob to `helpdesk` | **403** (CVE-2026-94000 fix intact) |

The Attack D control confirms the asymmetry the report describes: the 26.8.1 fix blocks
**group join** when the group carries admin-bearing composites, but mapping the same
composite **onto** the group (or onto a user directly) is not walked and returns 204.

> Note: when run via `make all`, Attack A escalates `limited-admin` first, so D's
> join-control is skipped (the identity is already admin). Run `attack-d` standalone on
> a fresh lab to observe the 403, as shown above.
