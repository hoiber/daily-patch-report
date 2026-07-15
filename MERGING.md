# Merging a feature branch to staging

This repo develops larger features on their own branch (e.g. `SVF-Merge`), each with its
own Railway environment for testing (its own `api-server` + `cve-dashboard` deploy, and
its own Postgres instance — see "Railway environments don't share anything" below).
When the feature is ready, it gets folded into `staging` for the shared staging deploy.

## Steps

1. **Fetch and check for divergence** — `staging` moves independently while you're working
   on the feature branch, so never assume a fast-forward:

   ```bash
   git fetch origin staging <feature-branch>
   git log --oneline origin/staging..<feature-branch>   # your commits
   git log --oneline <feature-branch>..origin/staging   # staging-only commits you don't have
   ```

   If the second command shows anything, `staging` has commits your branch doesn't —
   merge, don't force-push, or you'll silently drop them.

2. **Merge `origin/staging` into the feature branch** (not the other way around — you want
   to resolve conflicts on your branch, where you have full context on what you changed):

   ```bash
   git merge origin/staging -m "Merge origin/staging into <feature-branch>"
   ```

   Resolve any conflicts normally. Files likely to conflict: anything both branches touched
   independently (e.g. `layout.tsx` if both added sidebar entries) — usually a clean
   line-level resolution, not a real logical conflict.

3. **Typecheck** after resolving conflicts — a clean merge can still combine two changes
   into something that doesn't compile:

   ```bash
   pnpm run typecheck
   ```

4. **Bump the version** — every `package.json` in the workspace shares one version string
   (`YYMM.N` — year+month, incrementing release number within the month), plus
   `artifacts/cve-dashboard/src/lib/release-notes.ts` (`APP_VERSION` and a new
   `RELEASE_NOTES` entry summarizing what shipped). Bump all of them together in one commit.

5. **Push to `staging`, and sync the feature branch too** so it doesn't silently diverge
   from what you just shipped:

   ```bash
   git push origin <feature-branch>:staging
   git push origin <feature-branch>:<feature-branch>
   ```

   Pushing to `staging` triggers Railway's auto-deploy for the staging environment.

## Railway environments don't share anything

Each Railway environment (`production`, `staging`, `<feature-branch>`, ...) has its own
independent copy of every service, including Postgres — **environment variables and
database schema do not propagate between them.** If your feature branch added a new env
var or a new Postgres table, you must replicate that setup on `staging` (and later
`production`) yourself before the merged code will actually work there:

```bash
# Env vars — copy across explicitly, per environment:
railway variable set "SOME_VAR=value" --service <id> --environment staging \
  --project <project-id> --skip-deploys --json

# New/changed Drizzle schema — push against that environment's Postgres:
DATABASE_URL=$(railway variable list --service <postgres-id> --environment staging \
  --project <project-id> --json | python3 -c "import json,sys;print(json.load(sys.stdin)['DATABASE_PUBLIC_URL'])") \
  pnpm --filter @workspace/db run push
```

Use `--skip-deploys` when setting variables so you can batch multiple changes before
triggering a rebuild. Once you're ready, run **`railway service redeploy`** to pick them
up — see the pitfall below, `restart` does not.

## Pitfalls hit in practice

- **`railway service source connect --branch X --environment Y` is NOT scoped to that
  environment** despite the `--environment` flag — it changes the service's GitHub source
  branch globally, for every environment that uses that service. Setting a feature
  environment's `api-server` to a feature branch this way silently repointed
  production/staging/other environments' `api-server` at that branch too. If you need
  different branches per environment for the same service, do it from the Railway
  dashboard UI (which does support true per-environment source overrides) — don't use this
  CLI command for anything beyond a single-environment project.
- **`railway environment edit --service-config ... source.branch ...`** (the config-as-code
  diff/apply path) silently no-ops (`"No changes to apply"`) in this project, since it isn't
  using Railway's config-as-code system (`.railway/railway.ts`). Don't rely on it.
- Prefer pushing env var secrets through a shell variable and `--stdin` /
  `echo -n "$VALUE" | railway variable set KEY --stdin ...` rather than putting the raw
  value in a command that gets echoed back — keeps secrets out of shell history and tool
  output.
- **`railway service restart` does NOT pick up newly-set env vars** — it just restarts the
  existing already-built container, which only ever reads env vars once at boot. If a push
  triggered a build/deploy *before* you finished setting new vars (e.g. you pushed code,
  then set vars with `--skip-deploys`), the running instance is stuck on the old vars until
  you run **`railway service redeploy`** (rebuilds/relaunches, re-reading current vars).
  Order of operations to avoid this entirely: set all env vars and push the DB schema
  *before* pushing the code that depends on them, or just always `redeploy` afterward.
