# Base-image registry is overridable (e.g. --build-arg REGISTRY=mirror.gcr.io/library when Docker Hub rate-limits).
ARG REGISTRY=docker.io/library
# Build context is the repository root:  docker build -f api/Dockerfile .
FROM ${REGISTRY}/node:22-alpine AS web
WORKDIR /app/web
COPY web/package*.json web/tsconfig.json web/vite.config.ts web/index.html ./
RUN npm ci
COPY web/src ./src
RUN npm run build            # emits ../api/public

FROM ${REGISTRY}/node:22-alpine AS build
WORKDIR /app/api
COPY api/package*.json api/tsconfig*.json ./
RUN npm ci
COPY api/src ./src
RUN npm run build

FROM ${REGISTRY}/node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY api/package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/api/dist ./dist
COPY --from=web /app/api/public ./public
COPY api/migrations ./migrations
# Volume mount points must be writable by the unprivileged user (named volumes inherit this ownership).
RUN mkdir -p /anchor && chown node:node /anchor
USER node
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://127.0.0.1:3000/health || exit 1
CMD ["node", "dist/server.js"]
