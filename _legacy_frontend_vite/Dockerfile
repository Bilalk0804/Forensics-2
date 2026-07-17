# ============================================================================
# Frontend: Sentinel Forensics Dashboard
# React + TypeScript + Vite
# ============================================================================

FROM node:18-alpine as builder

WORKDIR /app

# Copy package files
COPY package.json bun.lockb* ./

# Install dependencies with bun or npm
RUN npm install

# Copy source code
COPY . .

# Build the application
RUN npm run build

# ============================================================================
# Production Stage
# ============================================================================

FROM node:18-alpine

WORKDIR /app

# Install serve to run the built app
RUN npm install -g serve

# Copy built application from builder
COPY --from=builder /app/dist ./dist

# Expose port
EXPOSE 5173

# Environment variables
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:5173/ || exit 1

# Start the application
CMD ["serve", "-s", "dist", "-l", "5173"]
