# Least-privilege runtime DB role + migration-as-Job (Phase 3c / T4)

Status: **role groundwork shipped; runtime cutover STAGED (not yet flipped).**

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

## Why the cutover is staged (read before flipping)

The policy is **fail-closed**: when `app.tenant_id` is unset, an RLS-enabled
table returns **zero rows** and **rejects writes** (`WITH CHECK`). RLS is enabled
on `roles, user_roles, oauth_clients, api_keys, refresh_tokens, memberships,
projects, audit_events, outbox`.

So the moment the app connects as the non-superuser `iam_app`, **every** access
to one of those tables that does *not* run inside a tenant-scoped transaction
will fail. Today that includes hot, pre-tenant paths:

| Path | Touches (RLS table) | Wrapped today? |
|------|---------------------|----------------|
| Login | `refresh_tokens` (write) | ❌ |
| Refresh | `refresh_tokens` (read+write) | ❌ |
| ValidateToken | `user_roles`, `memberships` (read) | ❌ |
| Register / bootstrap | `user_roles`, `memberships` (write) | ❌ |
| API-key validate | `api_keys`, `user_roles` (read) | ❌ |
| Tenant-admin writes (roles/perms/assign/projects/members) | various | ✅ Phase 3b |
| Project / member lists | `projects`, `memberships` | ✅ M6.4b |

**Prerequisite for cutover:** wrap the ❌ rows so each sets `app.tenant_id`
before touching an RLS table — either via `withTenant`/`with_tenant`, or by
setting the GUC once per request from the token's tenant claim. `refresh_tokens`
and `api_keys` need extra thought: they are keyed by `user_id` and managed across
tenants, so they likely need either per-row tenant context or an explicit RLS
policy exception. Do **not** point `POSTGRES_USER`/`DATABASE_URL` at `iam_app`
until this is done and verified, or the service will fail closed on login.

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

(The auth binary needs a `migrate` subcommand that runs the embedded migrations
and exits; the long-running Deployment then starts with auto-migrate disabled.)

## Cutover steps (operator, pure-GitOps)

1. Complete + verify the prerequisite wrapping (table above all ✅).
2. Add the `iam_app` password as a Secret key and enable login, run once as `app`:
   `ALTER ROLE iam_app WITH LOGIN PASSWORD '<from-secret>';`
3. Add `migrate-job.yaml`; disable auto-migrate on the Deployment.
4. Flip the app's connection string to `iam_app`:
   `AUTH_DATABASE_URL: postgres://iam_app:<secret>@postgres-auth:5432/auth_db?sslmode=disable`
5. Sync + rollout-restart `auth`. Smoke: login, `/me`, a tenant-admin write, and a
   cross-tenant read attempt (must be empty), with `iam_app` confirmed in
   `SELECT current_user`.

## Rollback

Point `AUTH_DATABASE_URL` back at `app`, re-enable auto-migrate, rollout-restart.
`iam_app` is `NOLOGIN` again (or left as-is — it is harmless unused). The
`000014` down-migration drops the role entirely.

## Scope note

This covers the auth database (the one that carries RLS). The user service
(`profiles`) is global/un-tenant-scoped, so it does not need RLS; giving it its
own least-privilege role is a smaller, independent follow-up.
