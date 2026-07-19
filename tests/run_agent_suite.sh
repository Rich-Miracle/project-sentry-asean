#!/usr/bin/env bash
# Phase 1 — agent-direct conformance suite (POST /evaluate).
# Cases are spaced: the local LLM is single-threaded (~25s/verdict).
GAP=${GAP:-15}
PASS=0; FAIL=0

printf "%-4s %-26s %-4s %-9s %-9s %-6s %s\n" "#" "CASE" "JUR" "EXPECT" "GOT" "RES" "PII"
printf '%.0s-' {1..96}; echo

run() {
  local n="$1" desc="$2" file="$3" jur="$4" cls="$5" ctype="$6" expect="$7"
  local resp verdict pii
  resp=$(docker exec sentry-core sh -c "
    P=\$(base64 -w0 /tmp/fixtures/$file)
    curl -s -m180 -X POST http://localhost:8080/evaluate \
      -H 'Content-Type: application/json' \
      -d '{\"flow_id\":\"suite-$n\",\"dest_ip\":\"10.0.0.$n\",\"jurisdiction\":\"$jur\",\"classification\":\"$cls\",\"content_bytes\":\"'\$P'\",\"content_type\":\"$ctype\"}'")
  verdict=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin)['verdict'])" 2>/dev/null || echo ERR)
  pii=$(echo "$resp" | python3 -c "import sys,json;print(','.join(json.load(sys.stdin)['pii_types'])[:34])" 2>/dev/null || echo "-")
  local res; if [ "$verdict" = "$expect" ]; then res="PASS"; PASS=$((PASS+1)); else res="FAIL"; FAIL=$((FAIL+1)); fi
  printf "%-4s %-26s %-4s %-9s %-9s %-6s %s\n" "$n" "$desc" "$jur" "$expect" "$verdict" "$res" "$pii"
  sleep "$GAP"
}

run A1  "text + NRIC"           text_pii.txt      US NON_EQUIVALENT   text/plain       BLOCK
run A2  "text + NRIC"           text_pii.txt      SG EQUIVALENT      text/plain       ALLOW
run A3  "text + NRIC"           text_pii.txt      MY EQUIVALENT      text/plain       BLOCK
run A4  "clean JSON"            text_clean.json   MY EQUIVALENT      application/json ALLOW
run A5  "clean JSON"            text_clean.json   US NON_EQUIVALENT  application/json BLOCK
run A6  "credit card"           text_cc.txt       US NON_EQUIVALENT  text/plain       BLOCK
run A7  "PDF + NRICs"           doc_pii.pdf       US NON_EQUIVALENT  application/pdf  BLOCK
run A8  "PDF clean"             doc_clean.pdf     MY EQUIVALENT      application/pdf  ALLOW
run A9  "IC image (OCR)"        ic_card.jpg       US NON_EQUIVALENT  image/jpeg       BLOCK
run A10 "photo, no text"        photo_notext.png  US NON_EQUIVALENT  image/png        BLOCK
run A11 "PDF mislabelled text"  doc_pii.pdf       US NON_EQUIVALENT  text/plain       BLOCK
run A12 "NRIC lookalikes"       lookalike.txt     MY EQUIVALENT      text/plain       ALLOW

echo
echo "PASS=$PASS  FAIL=$FAIL"
