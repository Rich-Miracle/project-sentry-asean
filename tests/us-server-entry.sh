#!/bin/bash
# us-server startup: generate cert, run the HTTPS upload target.
if [ ! -f /tmp/srv.pem ]; then
  openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem \
    -days 30 -nodes -subj "/CN=us-server" 2>/dev/null
  cat /tmp/k.pem /tmp/c.pem > /tmp/srv.pem
fi
exec python3 -u /tmp/upload_server.py
