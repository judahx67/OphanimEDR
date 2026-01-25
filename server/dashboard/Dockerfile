# Dashboard Dockerfile - Multi-stage build
# Stage 1: Build
FROM node:20-alpine as builder

WORKDIR /app

# Copy package files
COPY dashboard/package.json dashboard/package-lock.json* ./

# Install dependencies
RUN npm install

# Copy source code
COPY dashboard/ ./

# Build production bundle
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:alpine

# Copy built files
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx config
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
