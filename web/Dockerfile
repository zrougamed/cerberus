# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . .

# Build the frontend (Vite build)
# API calls go to /api/v1 which nginx proxies to Cerberus
RUN npm run build

# Production stage - nginx to serve static files
FROM nginx:alpine

# Copy built assets
COPY --from=builder /app/dist/public /usr/share/nginx/html

# Copy nginx configuration template
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose port 80
EXPOSE 80

# Use custom entrypoint to handle env var substitution
ENTRYPOINT ["/docker-entrypoint.sh"]
