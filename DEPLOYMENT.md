# Deployment Guide

This document covers deploying the Behaviour-Based Adaptive Authentication System to production environments.

## Pre-Deployment Checklist

- [ ] All tests passing (`test_edge_cases.py`, `auth_failure_demo.py`)
- [ ] `.env` configured with production secrets
- [ ] Database migrated and tested
- [ ] Redis cluster set up and accessible
- [ ] SSL/TLS certificates loaded
- [ ] Audit logging configured
- [ ] Monitoring and alerting enabled
- [ ] Backup strategy in place
- [ ] Disaster recovery plan documented

## Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ app/
COPY .env .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')"

# Run application
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose (Local Dev)

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: mysql+pymysql://auth_user:password@db:3306/auth_db
      REDIS_HOST: redis
    depends_on:
      - db
      - redis
    volumes:
      - .:/app

  db:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: auth_db
      MYSQL_USER: auth_user
      MYSQL_PASSWORD: password
      MYSQL_ROOT_PASSWORD: root_password
    ports:
      - "3306:3306"
    volumes:
      - db_data:/var/lib/mysql

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes

volumes:
  db_data:
```

### Build and Push

```bash
# Build
docker build -t chitchula/auth-system:latest .

# Tag for registry
docker tag chitchula/auth-system:latest registry.example.com/auth-system:latest

# Push to registry
docker push registry.example.com/auth-system:latest

# Deploy
docker pull registry.example.com/auth-system:latest
docker run -d \
  --name auth-app \
  --env-file .env.prod \
  -p 8000:8000 \
  registry.example.com/auth-system:latest
```

## Kubernetes Deployment

### Namespace & ConfigMap

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: auth-system

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
  namespace: auth-system
data:
  APP_NAME: "Behaviour-Based Authentication"
  DEBUG: "false"
  ALLOWED_ORIGINS: "https://api.example.com,https://app.example.com"
```

### Secret (for sensitive data)

```bash
kubectl create secret generic auth-secrets \
  --from-literal=SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))") \
  --from-literal=REFRESH_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))") \
  --from-literal=DATABASE_PASSWORD=strong-password \
  --from-literal=REDIS_PASSWORD=strong-password \
  -n auth-system
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-app
  namespace: auth-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-app
  template:
    metadata:
      labels:
        app: auth-app
    spec:
      containers:
      - name: auth-app
        image: registry.example.com/auth-system:latest
        ports:
        - containerPort: 8000
        
        # Environment variables
        env:
        - name: APP_NAME
          valueFrom:
            configMapKeyRef:
              name: auth-config
              key: APP_NAME
        - name: DATABASE_URL
          value: mysql+pymysql://auth_user:$(DB_PASSWORD)@auth-db:3306/auth_db
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: DATABASE_PASSWORD
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: SECRET_KEY
        - name: REDIS_HOST
          value: auth-redis
        
        # Resource limits
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        
        # Health checks
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Service & Ingress

```yaml
---
apiVersion: v1
kind: Service
metadata:
  name: auth-app-service
  namespace: auth-system
spec:
  selector:
    app: auth-app
  ports:
  - protocol: TCP
    port: 8000
    targetPort: 8000
  type: ClusterIP

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-app-ingress
  namespace: auth-system
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - api.example.com
    secretName: auth-tls-cert
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-app-service
            port:
              number: 8000
```

## AWS Deployment (ECS/Fargate)

### Task Definition

```json
{
  "family": "auth-system",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "auth-app",
      "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/auth-system:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "DATABASE_URL",
          "value": "mysql+pymysql://auth_user:password@auth-db.cluster-xxx.us-east-1.rds.amazonaws.com:3306/auth_db"
        },
        {
          "name": "REDIS_HOST",
          "value": "auth-redis.xxx.ng.0001.use1.cache.amazonaws.com"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/auth-system",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### ECS Service

```bash
aws ecs create-service \
  --cluster auth-prod \
  --service-name auth-app \
  --task-definition auth-system:1 \
  --desired-count 3 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-xxx],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:us-east-1:123456789:targetgroup/auth-tg/xxx,containerName=auth-app,containerPort=8000"
```

## Heroku Deployment

### Procfile

```
web: python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

### Deploy

```bash
# 1. Create Heroku app
heroku create auth-system-app

# 2. Add database add-on
heroku addons:create heroku-postgresql:standard-0 --app auth-system-app

# 3. Set environment variables
heroku config:set \
  SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))") \
  DEBUG=False \
  --app auth-system-app

# 4. Deploy
git push heroku main

# 5. Migrate database
heroku run python -m alembic upgrade head --app auth-system-app

# 6. View logs
heroku logs --tail --app auth-system-app
```

## Manual VPS Deployment (Ubuntu 22.04)

### 1. System Setup

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Python
sudo apt-get install -y python3.11 python3.11-venv python3-pip

# Install MySQL
sudo apt-get install -y mysql-server
sudo mysql_secure_installation

# Install Redis
sudo apt-get install -y redis-server

# Install Nginx
sudo apt-get install -y nginx

# Install certbot for SSL
sudo apt-get install -y certbot python3-certbot-nginx
```

### 2. Application Setup

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/Chitchula-Sai-Bhuvan/adaptive-authentication-system.git
cd adaptive-authentication-system

# Create virtual environment
sudo python3.11 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt

# Create .env
sudo cp .env.example .env
sudo nano .env  # Edit with production secrets

# Change ownership
sudo chown -R www-data:www-data /opt/adaptive-authentication-system
```

### 3. Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/auth-system.service
```

```ini
[Unit]
Description=Behaviour-Based Authentication System
After=network.target mysql.service redis-server.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/adaptive-authentication-system
EnvironmentFile=/opt/adaptive-authentication-system/.env
ExecStart=/opt/adaptive-authentication-system/.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 4. Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable auth-system
sudo systemctl start auth-system
sudo systemctl status auth-system
```

### 5. Nginx Configuration

```bash
sudo nano /etc/nginx/sites-available/auth-system
```

```nginx
server {
    listen 80;
    server_name api.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;
    
    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 6. Enable Nginx

```bash
sudo ln -s /etc/nginx/sites-available/auth-system /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Get SSL certificate
sudo certbot certonly --nginx -d api.example.com
```

## Database Backup Strategy

### MySQL Backup

```bash
# Daily backup
0 2 * * * /usr/bin/mysqldump -u auth_user -p$DB_PASSWORD auth_db | gzip > /backups/auth_db_$(date +\%Y\%m\%d).sql.gz

# Archive to S3
0 3 * * * aws s3 cp /backups/auth_db_$(date +\%Y\%m\%d).sql.gz s3://auth-backups/
```

### Point-in-Time Recovery

```bash
# Restore from backup
gunzip < /backups/auth_db_20260320.sql.gz | mysql -u auth_user -p auth_db

# Or restore from S3
aws s3 cp s3://auth-backups/auth_db_20260320.sql.gz - | gunzip | mysql -u auth_user -p auth_db
```

## Monitoring Setup

### Key Metrics to Monitor

```yaml
Metrics:
  - HTTP request latency (p50, p95, p99)
  - Error rate (4xx, 5xx responses)
  - Authentication success/failure rate
  - MFA fatigue attacks detected
  - Database connection pool usage
  - Redis memory usage
  - Audit log write latency
```

### Prometheus Configuration

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'auth-system'
    static_configs:
      - targets: ['localhost:8000']
```

---

**Deployment Checklist Complete!** 🚀

For questions, see [README.md](README.md) or [SECURITY.md](SECURITY.md).
