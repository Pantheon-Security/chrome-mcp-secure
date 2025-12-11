# Dockerfile for Smithery deployment
FROM node:20-slim

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy built files
COPY dist/ ./dist/

# Set user for security
USER node

# Default command
CMD ["node", "dist/index.js"]
