# ============================================================
# Secure Document Management & E-Signature System
# Frontend Dockerfile (React / Vite → nginx)
# ============================================================

# ---- Stage 1: Builder ----
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files first for layer caching
COPY frontend/package*.json ./

# Install all dependencies (including dev, needed for Vite build)
RUN npm ci --silent

# Copy source code
COPY frontend/ .

# Build production bundle
RUN npm run build

# ---- Stage 2: Runtime (nginx) ----
FROM nginx:alpine AS runtime

# Remove the default nginx welcome page
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom nginx configuration (SPA routing + proxy to backend)
COPY nginx/frontend.conf /etc/nginx/conf.d/default.conf

# Expose HTTP port
EXPOSE 80

# nginx starts in foreground by default
CMD ["nginx", "-g", "daemon off;"]
