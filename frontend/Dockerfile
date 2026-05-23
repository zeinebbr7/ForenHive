FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine

# Self-signed TLS cert so the SPA can be served over HTTPS.
# Chrome's HTTPS-First mode blocks PDF (blob:) downloads delivered over plain
# HTTP — even on localhost — so HTTPS is required for the certified-report
# download to work. CN/SAN = localhost (accept the one-time cert warning).
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout /etc/nginx/certs/forenhive.key \
      -out    /etc/nginx/certs/forenhive.crt \
      -subj "/C=TN/O=ForenHive/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY forenhive-locations.inc /etc/nginx/conf.d/forenhive-locations.inc
