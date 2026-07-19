#!/usr/bin/env bash
# Project Sentry ASEAN — transparent interception setup.
# Run AFTER ./start.sh. Restores both TLS paths (SMTPS + HTTPS file upload),
# the upload target, iptables redirects, and test fixtures.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
docker exec sentry-core sh -c 'mkdir -p /var/log/sentry; chmod 777 /var/log/sentry' 2>/dev/null

echo "[1/5] Regenerating test fixtures..."
docker cp "$ROOT/tests/make_fixtures.py" sentry-core:/tmp/make_fixtures.py >/dev/null
docker exec sentry-core /agent/.venv/bin/python /tmp/make_fixtures.py >/dev/null
# push a couple into workload for send tests
docker cp sentry-core:/tmp/fixtures/doc_pii.pdf /tmp/_f.pdf >/dev/null && docker cp /tmp/_f.pdf sentry-workload:/tmp/doc_pii.pdf >/dev/null
docker cp sentry-core:/tmp/fixtures/text_pii.txt /tmp/_f.txt >/dev/null && docker cp /tmp/_f.txt sentry-workload:/tmp/text_pii.txt >/dev/null
echo "      fixtures ready"

echo "[2/5] Upload target on us-server (HTTPS :8443)..."
docker cp "$ROOT/tests/upload_server.py" sentry-us-server:/tmp/upload_server.py >/dev/null
docker exec sentry-us-server sh -c '
  [ -f /tmp/srv.pem ] || { openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem -days 30 -nodes -subj "/CN=us-server" 2>/dev/null; cat /tmp/k.pem /tmp/c.pem > /tmp/srv.pem; }
  pgrep -f upload_server.py >/dev/null || (python3 /tmp/upload_server.py >/tmp/upload.log 2>&1 &)
  sleep 1; ss -tlnp 2>/dev/null | grep -q 8443 && echo "      8443 up" || echo "      8443 FAILED"
'

echo "[3/5] iptables redirects (SMTPS :465->:4465, HTTPS :8443->:4480)..."
docker exec sentry-workload sh -c '
  add() { iptables -t nat -C OUTPUT "$@" 2>/dev/null || iptables -t nat -A OUTPUT "$@"; }
  add -p tcp --dport 465  -m owner --uid-owner 999 -j RETURN
  add -p tcp --dport 465  -j REDIRECT --to-port 4465
  add -p tcp --dport 8443 -m owner --uid-owner 999 -j RETURN
  add -p tcp --dport 8443 -j REDIRECT --to-port 4480
  echo "      rules: $(iptables -t nat -L OUTPUT -n | grep -cE "REDIRECT")"
'

echo "[4/5] mitmproxy SMTPS (:4465)..."
docker exec sentry-core sh -c 'pkill -f "listen-port 4465" 2>/dev/null'; sleep 1
docker exec -d -u mitmuser -w /agent sentry-core sh -c \
  'PYTHONUNBUFFERED=1 /agent/.venv/bin/mitmdump --set confdir=/home/mitmuser/.mitmproxy \
   --ssl-insecure --mode transparent --listen-port 4465 \
   -s /agent/mitm_smtp_addon.py > /var/log/sentry/mitm-smtp.log 2>&1'

echo "[5/5] mitmproxy HTTPS (:4480)..."
docker exec sentry-core sh -c 'pkill -f "listen-port 4480" 2>/dev/null'; sleep 1
docker exec -d -u mitmuser -w /agent sentry-core sh -c \
  'PYTHONUNBUFFERED=1 /agent/.venv/bin/mitmdump --set confdir=/home/mitmuser/.mitmproxy \
   --ssl-insecure --mode transparent --listen-port 4480 \
   -s /agent/mitm_addon.py > /var/log/sentry/mitm-https.log 2>&1'
sleep 3

# --- HTTPS file-upload path ---
docker exec sentry-us-server sh -c '
  [ -f /tmp/srv.pem ] || { openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem -days 30 -nodes -subj "/CN=us-server" 2>/dev/null; cat /tmp/k.pem /tmp/c.pem > /tmp/srv.pem; }
  pgrep -f upload_server.py >/dev/null || (python3 /tmp/upload_server.py &)
'
docker exec sentry-workload sh -c '
  iptables -t nat -C OUTPUT -p tcp --dport 8443 -m owner --uid-owner 999 -j RETURN 2>/dev/null || iptables -t nat -A OUTPUT -p tcp --dport 8443 -m owner --uid-owner 999 -j RETURN
  iptables -t nat -C OUTPUT -p tcp --dport 8443 -j REDIRECT --to-port 4480 2>/dev/null || iptables -t nat -A OUTPUT -p tcp --dport 8443 -j REDIRECT --to-port 4480
'

echo
echo "Transparent interception ready:"
docker exec sentry-core sh -c 'ss -tlnp 2>/dev/null | grep -E "4465|4480" | awk "{print \"  \"\$4}"'
echo "Warming the model (first verdict is slow)..."
docker exec sentry-workload sh -c 'curl -sk -m90 -F "file=@/tmp/text_pii.txt" https://172.30.0.22:8443/upload >/dev/null 2>&1' &
echo "  (warm-up running in background)"

# Demo web console (Meridian Mail UI)
docker cp "$ROOT/demo-ui/demo_server.py" sentry-core:/agent/demo_server.py >/dev/null 2>&1
docker cp "$ROOT/demo-ui/index.html" sentry-core:/agent/index.html >/dev/null 2>&1
docker exec sentry-core sh -c 'pkill -f demo_server.py 2>/dev/null'; sleep 1
docker exec -d -w /agent sentry-core /agent/.venv/bin/python demo_server.py
echo "Demo UI: http://192.168.37.133:8090"
