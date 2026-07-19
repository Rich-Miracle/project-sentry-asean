#!/usr/bin/env bash
# ============================================================================
#  PROJECT SENTRY ASEAN — Control Console
# ============================================================================
ROOT="$(cd "$(dirname "$0")" && pwd)"
CF="$ROOT/compose/docker-compose.yml"
VMIP="192.168.37.133"

# ---- palette ---------------------------------------------------------------
B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
RED=$'\e[38;5;167m'; GRN=$'\e[38;5;71m'; YEL=$'\e[38;5;179m'
BLU=$'\e[38;5;110m'; TEA=$'\e[38;5;36m'; GRY=$'\e[38;5;244m'
WHT=$'\e[38;5;253m'
ON="${GRN}●${R}"; OFF="${RED}○${R}"; WARN="${YEL}◑${R}"

C(){ docker exec sentry-core sh -c "$1" 2>/dev/null; }
line(){ printf "${GRY}%s${R}\n" "────────────────────────────────────────────────────────────"; }

# ---- status probes ---------------------------------------------------------
dot(){ [ "$1" = up ] && echo "$ON" || { [ "$1" = warn ] && echo "$WARN" || echo "$OFF"; }; }

probe(){
  AGENT=$(C 'curl -s -m2 http://localhost:8080/health' | grep -q ok && echo up || echo down)
  SMTP=$(C 'pgrep -f "listen-port 4465" >/dev/null' && echo up || echo down)
  HTTPS=$(C 'pgrep -f "listen-port 4480" >/dev/null' && echo up || echo down)
  UI=$(C 'pgrep -f demo_server.py >/dev/null' && echo up || echo down)
  CTRL=$(C 'pgrep -f /controller/sentry-controller >/dev/null' && echo up || echo down)
  OLLAMA=$(docker exec sentry-ollama ollama ps 2>/dev/null | grep -q llama && echo up || echo down)
  GRAF=$(docker ps --filter name=sentry-grafana --filter status=running -q | grep -q . && echo up || echo down)
  LOKI=$(docker ps --filter name=sentry-loki --filter status=running -q | grep -q . && echo up || echo down)
  MAIL=$(docker exec sentry-mailserver sh -c 'ss -tlnp 2>/dev/null | grep -q :465' && echo up || echo down)
}

# ---- banner ----------------------------------------------------------------
banner(){
  clear
  printf "${TEA}${B}"
  cat <<'ART'
   ┌─────────────────────────────────────────────────────────┐
   │   ⬡  P R O J E C T   S E N T R Y   A S E A N            │
   │      content-aware PDPA egress enforcer                 │
   └─────────────────────────────────────────────────────────┘
ART
  printf "${R}"
}

statusbar(){
  probe
  printf "  ${D}enforcement${R}   $(dot $AGENT) agent   $(dot $SMTP) smtps   $(dot $HTTPS) https   $(dot $CTRL) ebpf\n"
  printf "  ${D}services   ${R}   $(dot $OLLAMA) ollama  $(dot $MAIL) postfix $(dot $UI) webui   \n"
  printf "  ${D}observ.    ${R}   $(dot $GRAF) grafana $(dot $LOKI) loki\n"
}

# ---- actions ---------------------------------------------------------------
act_start(){
  banner; echo "  ${B}Starting stack + interception${R}"; line
  "$ROOT/start.sh"
  "$ROOT/setup-transparent.sh"
  echo; echo "  ${GRN}Ready.${R}  Web console → ${BLU}http://$VMIP:8090${R}"
}

act_stop(){ banner; echo "  ${B}Stopping stack${R}"; line; cd "$ROOT" && docker compose -f "$CF" down; echo "  ${GRN}Stopped.${R}"; }

act_health(){
  banner; echo "  ${B}Component Health${R}"; line; probe
  printf "  %-22s %s\n" "AI agent (/evaluate)"   "$(dot $AGENT)"
  printf "  %-22s %s\n" "SMTPS interception"     "$(dot $SMTP)"
  printf "  %-22s %s\n" "HTTPS interception"     "$(dot $HTTPS)"
  printf "  %-22s %s\n" "eBPF controller"        "$(dot $CTRL) ${D}$([ $CTRL = down ] && echo '(start manually for eBPF path)')${R}"
  printf "  %-22s %s\n" "Ollama (llama3.2:3b)"   "$(dot $OLLAMA)"
  printf "  %-22s %s\n" "Postfix SMTPS :465"     "$(dot $MAIL)"
  printf "  %-22s %s\n" "Web console :8090"      "$(dot $UI)"
  printf "  %-22s %s\n" "Grafana :3000"          "$(dot $GRAF)"
  printf "  %-22s %s\n" "Loki (logs)"            "$(dot $LOKI)"
  echo; line
  printf "  ${D}redirect rules${R}  "
  docker exec sentry-workload sh -c 'iptables -t nat -L OUTPUT -n 2>/dev/null | grep -c REDIRECT' | sed 's/$/ active/'
  printf "  ${D}memory        ${R}  "; free -h | awk '/Mem:/{print $7" available / "$2" total"}'
  printf "  ${D}swap          ${R}  "; free -h | awk '/Swap:/{print $3" used"}'
}

act_demo(){
  banner; echo "  ${B}Live Demonstration${R}"; line
  echo "  ${GRY}warming model...${R}"
  docker exec sentry-workload sh -c 'curl -sk -m90 -F "file=@/tmp/doc_pii.pdf" https://172.30.0.22:8443/upload -o /dev/null 2>/dev/null'
  echo
  echo "  ${B}① Email with an NRIC → US recipient${R}"
  if docker exec sentry-workload python3 -u -c "
import smtplib,ssl
from email.message import EmailMessage
ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
m=EmailMessage();m['From']='staff@sentry.local';m['To']='partner@us-server';m['Subject']='Q3'
m.set_content('Customer: Tan Ah Kow, NRIC S8234567A')
s=smtplib.SMTP_SSL('172.30.0.10',465,timeout=60,context=ctx);s.send_message(m);s.quit()
" 2>/dev/null; then
    echo "     ${RED}✗ SENT (not blocked!)${R}"
  else
    echo "     ${GRN}✓ BLOCKED${R} — SMTP session terminated"
  fi
  C 'grep "verdict=" /var/log/sentry/mitm-smtp.log | tail -1' | sed 's/^/     '"${GRY}"'/;s/$/'"${R}"'/'
  echo
  echo "  ${B}② Customer PDF → US upload endpoint${R}"
  docker exec sentry-workload sh -c 'curl -sk -m60 -F "file=@/tmp/doc_pii.pdf" https://172.30.0.22:8443/upload -o /dev/null -w "     '"${GRN}"'✓ HTTP %{http_code}'"${R}"' — upload rejected\n"'
  C 'grep "verdict=" /var/log/sentry/mitm-https.log | tail -1' | sed 's/^/     '"${GRY}"'/;s/$/'"${R}"'/'
  echo
  echo "  ${D}Web console for interactive demo → ${BLU}http://$VMIP:8090${R}"
}

act_reports(){
  banner; echo "  ${B}Audit Reports${R}"; line
  local files; files=$(ls -1t "$ROOT/reports"/*.pdf 2>/dev/null)
  if [ -z "$files" ]; then echo "  ${GRY}none generated yet${R}"; return; fi
  echo "$files" | head -8 | nl -w3 -s'  ' | sed 's/^/  /'
  echo; printf "  open newest? [y/N] "; read -r a
  [ "$a" = y ] && xdg-open "$(echo "$files"|head -1)" 2>/dev/null
}

act_logs(){
  banner; echo "  ${B}Live Logs${R}"; line
  echo "   1  ${TEA}SMTPS${R} interception (:4465)"
  echo "   2  ${TEA}HTTPS${R} interception (:4480)"
  echo "   3  ${TEA}Agent${R}  /evaluate verdicts"
  echo "   4  ${TEA}All${R}    (grafana → http://$VMIP:3000)"
  echo; printf "  select ${D}(q to go back)${R} ▸ "; read -r l
  case $l in
    1) C 'tail -f /var/log/sentry/mitm-smtp.log' ;;
    2) C 'tail -f /var/log/sentry/mitm-https.log' ;;
    3) C 'tail -f /var/log/sentry/agent.log' ;;
    4) echo "  Loki live logs in Grafana → Explore → {path=~\"smtp|https|agent\"}"; sleep 3 ;;
  esac
}

# ---- main loop -------------------------------------------------------------
while true; do
  banner
  statusbar
  echo
  line
  printf "   ${B}1${R}  ${WHT}Start${R} stack + interception\n"
  printf "   ${B}2${R}  ${WHT}Stop${R} stack\n"
  printf "   ${B}3${R}  ${WHT}Health${R} check\n"
  printf "   ${B}4${R}  Run ${WHT}demo${R} (SMTPS + HTTPS)\n"
  printf "   ${B}5${R}  Audit ${WHT}reports${R}\n"
  printf "   ${B}6${R}  Live ${WHT}logs${R}\n"
  printf "   ${B}0${R}  ${D}Exit${R}\n"
  line
  printf "  ▸ "; read -r c
  case $c in
    1) act_start ;;
    2) act_stop ;;
    3) act_health ;;
    4) act_demo ;;
    5) act_reports ;;
    6) act_logs; continue ;;
    0) clear; exit 0 ;;
    *) continue ;;
  esac
  echo; printf "  ${D}press enter${R}"; read -r _
done
