#!/bin/sh
set -e

# Set default values if not provided
DOMAIN=${DOMAIN:-localhost}
EMAIL=${EMAIL:-noreply@example.com}
IS_IP=${IS_IP:-false}
STAGING=${STAGING:-false}

# Create required directories
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
mkdir -p /var/www/certbot
mkdir -p "${CERT_DIR}"
mkdir -p /usr/share/nginx/html/.well-known/acme-challenge

# Function to generate self-signed certificate
generate_self_signed() {
    echo "Generating self-signed certificate for: $1"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/privkey.pem" \
        -out "${CERT_DIR}/fullchain.pem" \
        -subj "/CN=$1" \
        -addext "subjectAltName=DNS:$1" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth"
}

# Check if we should use IP or domain
if [ "$IS_IP" = "true" ]; then
    generate_self_signed "$DOMAIN"
else
    echo "Setting up Let's Encrypt for domain: $DOMAIN"
    
    # Prepare certbot command
    CERTBOT_CMD="certbot certonly --webroot -w /var/www/certbot"
    
    # Add staging flag if enabled
    if [ "$STAGING" = "true" ]; then
        echo "Using Let's Encrypt staging server"
        CERTBOT_CMD="$CERTBOT_CMD --staging"
    fi
    
    # Complete the certbot command
    CERTBOT_CMD="$CERTBOT_CMD --email ${EMAIL} --agree-tos --no-eff-email -d ${DOMAIN} --force-renewal"
    
    # Generate a temporary self-signed certificate to allow nginx to start
    echo "Generating temporary self-signed certificate..."
    generate_self_signed "$DOMAIN"
    
    # Start nginx in background
    echo "Starting nginx..."
    nginx -g "daemon on;"
    
    # Wait for nginx to start
    sleep 5
    
    # Request certificates
    echo "Requesting Let's Encrypt certificates..."
    echo "Running: $CERTBOT_CMD"
    $CERTBOT_CMD || {
        echo "Failed to obtain certificates. Using self-signed certificate."
        # Keep the self-signed certificate we already generated
    }
    
    # Stop nginx
    echo "Stopping nginx..."
    nginx -s stop
    
    # Create symlinks for nginx
    echo "Setting up certificate symlinks..."
    ln -sf "${CERT_DIR}/privkey.pem" /etc/letsencrypt/privkey.pem
    ln -sf "${CERT_DIR}/fullchain.pem" /etc/letsencrypt/fullchain.pem
    
    # Set up automatic renewal
    echo "0 0 * * * certbot renew --quiet --deploy-hook 'nginx -s reload'" > /etc/crontabs/root
    crond
fi

# Set proper permissions
chmod 400 "${CERT_DIR}/privkey.pem"

# Verify certificate files
echo "Verifying certificate files in ${CERT_DIR}:"
ls -la "${CERT_DIR}/"

# Start nginx in foreground
echo "Starting nginx in foreground..."
exec nginx -g "daemon off;"