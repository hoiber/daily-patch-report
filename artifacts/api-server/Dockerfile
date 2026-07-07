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

# PORT must be set as a variable on the Railway service (Railway does not
# inject it automatically just from generating a domain); index.ts requires
# it and refuses to start otherwise.
EXPOSE 8080
CMD ["node", "--enable-source-maps", "dist/index.mjs"]
