#!/bin/sh
# This script will be copied to the container and used to set up nginx
cp /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.bak
envsubst '${DOMAIN}' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf