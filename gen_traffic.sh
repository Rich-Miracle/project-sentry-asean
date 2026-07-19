#!/usr/bin/env bash
# Generate demo enforcement events for the Grafana dashboard.
set -u

send() {
  local id="$1" ip="$2" jur="$3" cls="$4" ctype="$5" text="$6"
  local b64; b64=$(printf '%s' "$text" | base64 -w0)
  docker exec sentry-core sh -c "curl -s -m180 -X POST http://localhost:8080/evaluate \
    -H 'Content-Type: application/json' \
    -d '{\"flow_id\":\"$id\",\"dest_ip\":\"$ip\",\"dest_port\":8080,\"jurisdiction\":\"$jur\",\"classification\":\"$cls\",\"content_bytes\":\"$b64\",\"content_type\":\"$ctype\",\"timestamp\":\"$(date -u +%FT%TZ)\"}'" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"  {d['verdict']:5} | {d['pdpa_clause']:20} | {','.join(d['pii_types'])}\")" 2>/dev/null \
    || echo "  (failed)"
}

echo "=== T1: PII -> US (expect BLOCK) ==="
send "t1-$RANDOM" "172.30.0.22" "US" "NON_EQUIVALENT" "text/plain" \
  "Customer record: Tan Ah Kow, NRIC S8234567A, phone +6591234567"
sleep 15

echo "=== T2: PII -> MY (expect reasoning) ==="
send "t2-$RANDOM" "172.30.0.21" "MY" "EQUIVALENT" "text/plain" \
  "Employee: Lim Wei Ming, NRIC S9123456B, email lim@corp.sg"
sleep 15

echo "=== T3: no PII -> MY (expect ALLOW) ==="
send "t3-$RANDOM" "172.30.0.21" "MY" "EQUIVALENT" "application/json" \
  '{"metric":"cpu_usage","value":42,"host":"web-01"}'
sleep 15

echo "=== T4: no PII -> US (expect precautionary BLOCK) ==="
send "t4-$RANDOM" "172.30.0.22" "US" "NON_EQUIVALENT" "application/json" \
  '{"metric":"disk_free","value":88}'
sleep 15

echo "=== T5: PII -> SG (expect ALLOW, domestic) ==="
send "t5-$RANDOM" "172.30.0.20" "SG" "EQUIVALENT" "text/plain" \
  "Internal record: Siti Nurhaliza, NRIC S7654321C"
sleep 15

echo "=== T6: credit card -> US (expect BLOCK, high sensitivity) ==="
send "t6-$RANDOM" "172.30.0.22" "US" "NON_EQUIVALENT" "text/plain" \
  "Payment: card 4532015112830366, holder Rajesh Kumar, NRIC S8801234D"
sleep 15

echo
echo "Done. Check the dashboard."
