#!/usr/bin/env bash
# ============================================================
# Project Sentry ASEAN - Health Check (Steps 1-3)
# Verifies everything built so far: testbed, eBPF hook, loader.
# Run from:  project-sentry-asean/
# Usage:     bash healthcheck_step1-3.sh
# ============================================================

PASS="[ PASS ]"
FAIL="[ FAIL ]"
INFO="[ INFO ]"
ok=0; bad=0

check() {  # check "label" "command"  -> pass if command exits 0
  if eval "$2" >/dev/null 2>&1; then
    echo "$PASS $1"; ok=$((ok+1))
  else
    echo "$FAIL $1"; bad=$((bad+1))
  fi
}

echo "============================================================"
echo " STEP 1 - Testbed environment (6 containers + network)"
echo "============================================================"

# All 6 containers exist and are running.
for c in sentry-workload sentry-core sentry-mailserver \
         sentry-sg-server sentry-my-server sentry-us-server; do
  check "container running: $c" \
    "docker inspect -f '{{.State.Running}}' $c | grep -q true"
done

# The bridge network exists.
check "network exists: sentry-asean_sentry-net" \
  "docker network inspect sentry-asean_sentry-net"

# Fixed IPs assigned as per jurisdiction.yaml.
echo "$INFO assigned container IPs:"
docker network inspect sentry-asean_sentry-net \
  --format '{{range .Containers}}        {{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}' \
  2>/dev/null

# Workload can reach the jurisdiction servers (real connectivity).
for ip in 172.30.0.20 172.30.0.21 172.30.0.22 172.30.0.10; do
  check "workload -> $ip reachable" \
    "docker exec sentry-workload ping -c1 -W2 $ip"
done

# sentry shares workload's network namespace (Option 2 decision).
check "sentry shares workload netns (network_mode)" \
  "docker inspect -f '{{.HostConfig.NetworkMode}}' sentry-core | grep -q 'container:'"

echo
echo "============================================================"
echo " STEP 2 - eBPF kernel hook (tc_hook.c -> tc_hook.o)"
echo "============================================================"

# Source files present.
check "kernel/tc_hook.c exists"      "test -f kernel/tc_hook.c"
check "kernel/tc_hook.h exists"      "test -f kernel/tc_hook.h"
check "kernel/Makefile exists"       "test -f kernel/Makefile"

# Compiled object exists and is a valid BPF ELF.
check "kernel/tc_hook.o compiled"    "test -f kernel/tc_hook.o"
check "tc_hook.o is eBPF ELF" \
  "file kernel/tc_hook.o | grep -qi 'eBPF'"

# v2 alignment: flow_map present, pending_map gone, no 443 skip.
check "v2: flow_map present in source" \
  "grep -q 'flow_map' kernel/tc_hook.c"
check "v2: pending_map fully removed" \
  "! grep -q 'pending_map' kernel/tc_hook.c"
check "v2: port-443 skip removed" \
  "! grep -q '443' kernel/tc_hook.c"

# Required sections present in the object.
check "tc_hook.o has 'tc' program section" \
  "llvm-objdump -h kernel/tc_hook.o | grep -qw 'tc'"
check "tc_hook.o has '.maps' section" \
  "llvm-objdump -h kernel/tc_hook.o | grep -qF '.maps'"
check "tc_hook.o has '.BTF' section" \
  "llvm-objdump -h kernel/tc_hook.o | grep -qF '.BTF'"

echo
echo "============================================================"
echo " STEP 3 - Go controller / loader (main.go + ebpf_loader.go)"
echo "============================================================"

# Source files present (Section 6 split).
check "controller/main.go exists"        "test -f controller/main.go"
check "controller/ebpf_loader.go exists" "test -f controller/ebpf_loader.go"
check "controller/go.mod exists"         "test -f controller/go.mod"

# Built binary exists inside the sentry container.
check "sentry-controller binary built (in container)" \
  "docker exec sentry-core test -f /controller/sentry-controller"

# tc_hook.o was copied next to the binary for loading.
check "tc_hook.o present in container /controller" \
  "docker exec sentry-core test -f /controller/tc_hook.o"

# Is the controller currently running? (informational - not a pass/fail)
if docker exec sentry-core pgrep -f sentry-controller >/dev/null 2>&1; then
  echo "$INFO controller is RUNNING - hook is attached, egress enforced"
  echo "$INFO   (to inspect maps: bpftool map dump name flow_map)"
else
  echo "$INFO controller is STOPPED - start it to attach the hook:"
  echo "$INFO   docker exec -w /controller sentry-core ./sentry-controller"
fi

echo
echo "============================================================"
echo " SUMMARY"
echo "============================================================"
echo " Passed: $ok    Failed: $bad"
if [ "$bad" -eq 0 ]; then
  echo " RESULT: Steps 1-3 all green. Ready for Step 4."
else
  echo " RESULT: $bad check(s) failed - review [ FAIL ] lines above."
fi
echo "============================================================"
