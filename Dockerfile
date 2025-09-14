# syntax=docker/dockerfile:1

# Install production dependencies separately to leverage Docker layer caching
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS runner
ENV NODE_ENV=production
ENV PORT=8000
WORKDIR /app

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source
COPY . .

# Drop privileges
RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app
USER app

EXPOSE 8000

# Basic healthcheck (adjust path if needed)
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://localhost:${PORT}/report/supported-checks || exit 1

CMD ["node", "index.js"]


