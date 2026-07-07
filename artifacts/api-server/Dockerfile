# Build context is the repo root (this is a pnpm workspace; api-server depends
# on workspace packages lib/db and lib/api-zod via `workspace:*`).
# Railway service settings: leave "Root Directory" unset (repo root) and set
# "Dockerfile Path" to artifacts/api-server/Dockerfile.

FROM node:24-slim AS build
WORKDIR /app
RUN corepack enable

COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @workspace/api-server run build

# esbuild bundles everything the server needs (including the pino worker
# transports) into artifacts/api-server/dist — no node_modules required to run it.
FROM node:24-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/artifacts/api-server/dist ./dist

# Railway injects PORT at runtime; index.ts requires it to be set.
CMD ["node", "--enable-source-maps", "dist/index.mjs"]
