# Least-privilege runtime DB role + migration-as-Job (Phase 3c / T4)

Status: **app-side complete — hot paths wrapped, RLS tables reclassified, migrate
subcommand + cutover tests shipped. Only the operator's connection-role flip
(`AUTH_DATABASE_URL` → `iam_app`) remains.**

## Problem

The auth service connects to Postgres as `app`, which is a **superuser** in our
deployment (`POSTGRES_USER=app`). A superuser **bypasses Row-Level Security**
even when the table has `FORCE ROW LEVEL SECURITY`. So the `tenant_isolation`
policy added in M6 only actually enforces inside the `iam_rls` transactions that
`withTenant` / `with_tenant` open (the tenant-scoped reads from M6.4b and, since
Phase 3b, the tenant-admin writes). Every other query runs with RLS bypassed and
is protected only by its own `WHERE tenant_id = …` clause.

Defense-in-depth is only real once the **connection role is itself a
non-superuser**, so RLS applies to every statement by default and a forgotten
tenant filter cannot leak or cross-write.

## What shipped (migration `000014` / `0014`)

A prepared least-privilege role:

```sql
CREATE ROLE iam_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE <db> TO iam_app;
GRANT USAGE ON SCHEMA public TO iam_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO iam_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO iam_app;
GRANT iam_rls TO iam_app;   -- so `SET LOCAL ROLE iam_rls` inside withTenant still works
```

It is created **`NOLOGIN`**: nothing can connect as `iam_app` until the operator
deliberately enables it at cutover. The migration is therefore safe to deploy now
— it only prepares the role.

## RLS table classification (migration `000016`)

The original fail-closed policy (`000013`) covered nine tables. Some are looked up
by a **non-tenant key before the tenant is known** — a chicken-and-egg the
fail-closed policy cannot satisfy once the superuser bypass is gone. So `000016`
splits them:

- **Kept fail-closed (strict tenant RLS):** `roles`, `user_roles`, `projects`.
  Always accessed with a known tenant. This is the defense-in-depth that survives
  a forgotten `WHERE` once we run as `iam_app`.
- **Relaxed to permissive `USING(true)`:** `refresh_tokens`, `api_keys` (looked up
  by an unguessable secret hash), `oauth_clients` (looked up by `client_id` to
  *discover* its tenant), `memberships` (looked up by `user_id` across tenants at
  login), `audit_events`, `outbox` (append-only system tables, pre-tenant /
  cross-tenant). Their boundary is the secret hash + the app-layer `WHERE`
  filters that already exist, **not** tenant RLS.

## App-side wrapping (shipped)

Every pre-tenant / hot path that reads or writes a **Kept-strict** table now sets
`app.tenant_id` with the tenant it already knows, so it keeps working once the
connection role is the non-superuser `iam_app`:

| Path | Kept-strict access | Tenant source | Wrapped |
|------|--------------------|---------------|---------|
| ValidateToken | GetUserRolesScoped, GetUserPermissionsScoped | token claim | ✅ `withTenantGUC` |
| ValidateApiKey | GetUserPermissionsScoped | key's pinned tenant | ✅ `withTenantGUC` |
| Register / BootstrapAdmin / BootstrapDemo | AssignRoleToUser | default tenant | ✅ `set_config` in tx |
| Tenant-admin writes (roles/perms/assign/projects/members) | various | active tenant | ✅ Phase 3b `withTenant` |
| Project / member lists | `projects` | active tenant | ✅ M6.4b `withTenant` |
| Login / Refresh / Logout / OIDC | only relaxed tables | — | n/a (no Kept-strict access) |

`withTenantGUC` sets `app.tenant_id` only — unlike `withTenant` it does **not**
`SET LOCAL ROLE iam_rls`. While the app still connects as the superuser `app` this
is a **no-op** (superuser bypasses RLS), so behaviour is unchanged until the
connection-role flip; the GUC only starts enforcing once we connect as `iam_app`.

Proven by `internal/db/iamapp_cutover_test.go` (integration): a second connection
as `iam_app` sees **zero** Kept-strict rows without `app.tenant_id`, sees the
relaxed tables fine, and a cross-tenant write is rejected by `WITH CHECK`.

## Migration-as-Job (decouple DDL from the runtime)

Once the app runs as the least-privileged `iam_app`, it can no longer run
migrations (they create roles, alter policies, etc.). Move migrations into a
one-shot Job that connects as the privileged owner (`app`), and strip the
auto-migrate-on-startup from the app. Ready-to-apply manifest:

```yaml
# iam-gitops/k8s/go/migrate-job.yaml  (ArgoCD: use a PreSync hook or a versioned Job name)
apiVersion: batch/v1
kind: Job
metadata:
  name: auth-migrate
  namespace: iam-go
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  backoffLimit: 3
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: ghcr.io/malvinpratama/iam-go-auth:latest
          command: ["/app/auth", "migrate"]          # a migrate-only entrypoint
          envFrom:
            - configMapRef: { name: app-config }       # AUTH_DATABASE_URL as `app` (owner)
            - secretRef:    { name: app-secrets }
```

The auth binary has the **`migrate` subcommand** (`/app/auth migrate`) — it runs
the embedded migrations and exits (skipping security validation / tracer /
metrics). The long-running Deployment skips startup migrations when
**`AUTO_MIGRATE=false`**; the default is `true`, so nothing changes until both the
Job and the flag are wired in gitops at cutover.

## Cutover steps (operator, pure-GitOps)

The app-side prerequisites are all shipped (wrapping ✅, reclass ✅, `migrate`
subcommand ✅, cutover tests ✅). What remains is operator-only and reversible:

1. **Deploy the wrapping first.** Bump the `iam-go-auth` image pin in
   `k8s/go/kustomization.yaml` to the merged 3c build and let ArgoCD sync. This is
   a no-op behaviourally (still connecting as `app`), but it must be live before
   the flip so the GUC-setting code is running.
2. **Enable `iam_app` login.** Generate a password, seal it into `app-secrets`
   (e.g. key `IAM_APP_DB_PASSWORD`), and run once as `app`:
   `ALTER ROLE iam_app WITH LOGIN PASSWORD '<from-secret>';`
3. **Move migrations to the Job.** Add `k8s/go/migrate-job.yaml` (PreSync hook,
   connects as `app`) and set `AUTO_MIGRATE=false` on the `auth` Deployment env.
4. **Flip the connection string** to `iam_app`:
   `AUTH_DATABASE_URL: postgres://iam_app:<secret>@postgres-auth:5432/auth_db?sslmode=disable`
5. **Sync + rollout-restart `auth`.** Smoke: `SELECT current_user` (= `iam_app`,
   non-superuser), login + `/me`, a tenant-admin write, and a cross-tenant read
   attempt (must be empty). The login path proves the wrapped hot paths work under
   the non-superuser role.

## Rollback

Point `AUTH_DATABASE_URL` back at `app`, re-enable auto-migrate, rollout-restart.
`iam_app` is `NOLOGIN` again (or left as-is — it is harmless unused). The
`000014` down-migration drops the role entirely.

## Scope note

This covers the auth database (the one that carries RLS). The user service
(`profiles`) is global/un-tenant-scoped, so it does not need RLS; giving it its
own least-privilege role is a smaller, independent follow-up.
