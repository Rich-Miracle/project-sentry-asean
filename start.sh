#!/usr/bin/env bash
# Project Sentry ASEAN — bring the whole system up in the correct order.
set -e
cd "$(dirname "$0")/compose"

echo "[1/5] Starting workload (netns host for sentry)..."
docker compose up -d workload
sleep 3

echo "[2/5] Starting sentry (shares workload netns)..."
docker compose up -d sentry
sleep 3

echo "[3/5] Starting remaining containers..."
docker compose up -d
sleep 3
echo "[3.5/5] Configuring Postfix (SMTPS on 465)..."
# Wait for the mailserver container's postfix to be installed & up
for i in $(seq 1 20); do
  docker exec sentry-mailserver sh -c 'command -v postconf >/dev/null 2>&1' && break
  sleep 3
done
docker exec sentry-mailserver sh -c '
  postconf -e "myhostname = mail.sentry.local"
  postconf -e "mydestination = mail.sentry.local, localhost"
  postconf -e "mynetworks = 127.0.0.0/8, 172.30.0.0/24"
  postconf -e "inet_interfaces = all"
  postconf -e "smtpd_tls_security_level = may"
  postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem"
  postconf -e "smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key"
  postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject"
  postconf -M "smtps/inet=smtps inet n - y - - smtpd" 2>/dev/null
  postconf -P "smtps/inet/smtpd_tls_wrappermode=yes"
  postconf -P "smtps/inet/smtpd_sasl_auth_enable=no"
  service postfix restart
' >/dev/null 2>&1
# Verify 465 actually came up
for i in $(seq 1 10); do
  docker exec sentry-mailserver sh -c 'ss -tlnp 2>/dev/null | grep -q :465' && { echo "      Postfix SMTPS ready (465 up)"; break; }
  sleep 2
  [ "$i" = 10 ] && echo "      WARNING: port 465 not listening"
done

echo "[4/5] Warming the local LLM..."
docker exec sentry-core sh -c \
  'curl -s -m180 http://172.30.0.50:11434/api/generate \
   -d "{\"model\":\"llama3.2:3b\",\"prompt\":\"ready\",\"stream\":false}" >/dev/null' \
  && echo "      LLM warm"

echo "[5/5] Starting the AI agent..."
docker exec -d -w /agent sentry-core sh -c 'PYTHONUNBUFFERED=1 /agent/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080 > /var/log/sentry/agent.log 2>&1'
echo "      waiting for agent..."
for i in $(seq 1 20); do
  if docker exec sentry-core sh -c 'curl -s -m3 http://localhost:8080/health' 2>/dev/null | grep -q ok; then
    echo "      agent ready"
    break
  fi
  sleep 5
done

echo
echo "System up. Verify:"
docker exec sentry-core ip -o link show | grep eth0 || echo "  WARNING: eth0 missing"
echo
echo "To start the controller:"
echo "  docker exec -w /controller sentry-core ./sentry-controller"
echo "  (add -test-mirror=172.30.0.20 for live pipeline testing)"
