FROM node:22-alpine AS builder

WORKDIR /app

# Copy monorepo manifests, scripts, and schemas
COPY package*.json turbo.json tsconfig.json ./
COPY scripts/ ./scripts/
COPY .aegis/ ./.aegis/
COPY packages/ ./packages/
COPY services/ ./services/

# Install dependencies and build
RUN npm install
RUN npm run build

FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8787

# Create dedicated non-root user and group with UID >= 10000
RUN addgroup -g 10001 -S aegis && adduser -u 10001 -S aegis -G aegis

COPY --from=builder --chown=10001:10001 /app/package.json ./
COPY --from=builder --chown=10001:10001 /app/node_modules ./node_modules
COPY --from=builder --chown=10001:10001 /app/packages ./packages
COPY --from=builder --chown=10001:10001 /app/services/gateway/dist ./services/gateway/dist

# Ensure writable temporary and cache directories with proper permissions
RUN mkdir -p /tmp /app/.aegis && chown -R 10001:10001 /tmp /app/.aegis

USER 10001:10001

EXPOSE 8787

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8787/api/health || exit 1

CMD ["node", "services/gateway/dist/index.js"]
