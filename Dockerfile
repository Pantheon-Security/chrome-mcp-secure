# Dockerfile for Smithery deployment
FROM node:20-slim

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ALL dependencies (including dev for build)
RUN npm ci

# Copy source files
COPY src/ ./src/
COPY tsconfig.json ./

# Build TypeScript
RUN npm run build

# Set user for security
USER node

# Default command
CMD ["node", "dist/index.js"]
