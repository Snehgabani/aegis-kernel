# Aegis Invariant Kernel: Enterprise Self-Hosted Gateway Container
FROM node:20-alpine AS builder

WORKDIR /app

# Copy monorepo manifests
COPY package.json turbo.json tsconfig.json ./
COPY packages/core ./packages/core
COPY packages/mcp ./packages/mcp
COPY packages/langchain ./packages/langchain
COPY packages/openai ./packages/openai
COPY packages/anthropic ./packages/anthropic
COPY packages/evals ./packages/evals
COPY packages/cli ./packages/cli
COPY services/gateway ./services/gateway

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
