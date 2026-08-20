# 🛡️ Aegis Gateway — Multi-Stage Production Container
FROM node:26-alpine AS builder

WORKDIR /app

# Copy root configurations, scripts, and workspace definitions
COPY package*.json tsconfig.json turbo.json ./
COPY scripts/ ./scripts/
COPY .aegis/ ./.aegis/
COPY packages/ ./packages/
COPY services/ ./services/

# Install dependencies and build monorepo packages
RUN npm install --no-audit --no-fund && npx turbo run build --no-daemon --concurrency=1

# Stage 2: Minimal Production Runtime
FROM node:26-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8787

# Upgrade all Alpine OS packages (libssl3, libcrypto3, busybox, etc.) to eliminate CVEs
# and create dedicated non-root user 10001:10001
RUN apk upgrade --no-cache && \
    addgroup -g 10001 -S aegis && \
    adduser -u 10001 -S aegis -G aegis && \
    mkdir -p /tmp /app/.aegis && \
    chown -R 10001:10001 /tmp /app/.aegis

# Copy built distribution files and required runtime packages
COPY package*.json ./
COPY --from=builder --chown=10001:10001 /app/node_modules ./node_modules
COPY --from=builder --chown=10001:10001 /app/packages/core/dist ./packages/core/dist
COPY --from=builder --chown=10001:10001 /app/packages/core/packs ./packages/core/packs
COPY --from=builder --chown=10001:10001 /app/packages/core/package.json ./packages/core/package.json
COPY --from=builder --chown=10001:10001 /app/services/gateway/dist ./services/gateway/dist
COPY --from=builder --chown=10001:10001 /app/services/gateway/package.json ./services/gateway/package.json

USER 10001:10001

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8787/api/health || exit 1

CMD ["node", "services/gateway/dist/index.cjs"]
