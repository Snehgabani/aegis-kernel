# 🛡️ Aegis Gateway — Multi-Stage Production Container
FROM node:22-alpine AS builder

WORKDIR /app

# Copy root configurations and workspace definitions
COPY package*.json tsconfig.json turbo.json ./
COPY packages/ ./packages/
COPY services/ ./services/

# Install dependencies and build monorepo packages
RUN npm ci && npm run build

# Stage 2: Minimal Production Runtime
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8787

# Copy built distribution files and required runtime packages
COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/core/packs ./packages/core/packs
COPY --from=builder /app/packages/core/package.json ./packages/core/package.json
COPY --from=builder /app/services/gateway/dist ./services/gateway/dist
COPY --from=builder /app/services/gateway/package.json ./services/gateway/package.json

EXPOSE 8787

USER node

CMD ["node", "services/gateway/dist/index.cjs"]
