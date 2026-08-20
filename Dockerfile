FROM node:26-alpine AS builder

WORKDIR /app

# Copy monorepo manifests, scripts, and schemas
COPY package*.json turbo.json tsconfig.json ./
COPY scripts/ ./scripts/
COPY .aegis/ ./.aegis/
COPY packages/ ./packages/
COPY services/ ./services/

# Install dependencies and build
RUN npm install && npm run build

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

COPY --from=builder --chown=10001:10001 /app/package.json ./
COPY --from=builder --chown=10001:10001 /app/node_modules ./node_modules
COPY --from=builder --chown=10001:10001 /app/packages ./packages
COPY --from=builder --chown=10001:10001 /app/services/gateway/dist ./services/gateway/dist

USER 10001:10001

EXPOSE 8787

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8787/api/health || exit 1

CMD ["node", "services/gateway/dist/index.js"]
