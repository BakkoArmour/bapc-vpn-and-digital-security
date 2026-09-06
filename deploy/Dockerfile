# Single shared image for every control-plane service in this repository.
# Each service is the same image run with a different `command:` (see
# docker-compose.yml) — there is no per-service Dockerfile to keep in sync.
#
# Not included here: the endpoint agent (src/runtime/agent.ts). It belongs on
# the host it protects (see installers/linux, installers/windows) because it
# manipulates that host's own network stack — containerizing it would defeat
# the point.

FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
COPY tests ./tests
COPY services ./services
COPY apps ./apps
COPY agents ./agents
COPY integrations ./integrations
COPY native ./native
COPY contracts ./contracts
COPY scripts ./scripts
RUN npm run build

FROM node:22-alpine AS prod-deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:22-alpine
RUN addgroup -S bapc && adduser -S -G bapc bapc
WORKDIR /app
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./package.json
# Runtime-loaded assets that are not TypeScript and so aren't in dist/:
# grpc-server.ts reads contracts/mesh.proto from disk at startup, and
# admin-console-server.ts serves apps/security-soc/public directly.
COPY contracts ./contracts
COPY apps/security-soc/public ./apps/security-soc/public
COPY db ./db
USER bapc
ENV NODE_ENV=production
EXPOSE 8080 50051 51900 1080 8181 8090
CMD ["node","dist/src/runtime/production-server.js"]
