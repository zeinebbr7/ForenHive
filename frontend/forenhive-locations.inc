# Shared location blocks, included by the HTTP (:80) server block in nginx.conf.

# Proxy API and health check to FastAPI backend
location /api/ {
    proxy_pass         http://forenhive-backend:8000;
    proxy_http_version 1.1;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
}

location /health {
    proxy_pass         http://forenhive-backend:8000;
    proxy_set_header   Host $host;
}

# Hashed bundles in /assets/ — safe to cache forever (filename changes on rebuild)
location /assets/ {
    try_files $uri =404;
    add_header Cache-Control "public, max-age=31536000, immutable";
}

# HTML files — never cache (always fetch fresh)
location ~* \.html$ {
    try_files $uri =404;
    add_header Cache-Control "no-cache, no-store, must-revalidate";
    add_header Pragma "no-cache";
    expires 0;
}

# SPA fallback — React Router handles client-side routes.
# Critically: also send no-cache headers, because this block serves
# index.html for any non-asset path (/, /stats, /reporting, …) and the
# \.html$ block above never matches those URLs.
location / {
    try_files $uri $uri/ /index.html;
    add_header Cache-Control "no-cache, no-store, must-revalidate" always;
    add_header Pragma "no-cache" always;
    expires 0;
}
