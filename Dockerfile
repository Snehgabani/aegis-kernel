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

FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8787

COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/services/gateway/dist ./services/gateway/dist

EXPOSE 8787

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8787/api/health || exit 1

CMD ["node", "services/gateway/dist/index.js"]
