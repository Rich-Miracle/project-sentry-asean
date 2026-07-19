#!/usr/bin/env bash
# Verify the stack is fully down before a clean restart.
echo "=== Container status ==="
running=$(docker ps --filter "name=sentry-" --format '{{.Names}}')
if [ -z "$running" ]; then echo "  OK: no sentry containers running"
else echo "  STILL UP:"; echo "$running" | sed 's/^/    /'; fi

echo "=== Orphaned host processes ==="
for p in mitmdump sentry-controller uvicorn; do
  # these run inside containers, so check via docker if any container is up
  :
done
echo "  (processes live inside containers; gone once containers are down)"

echo "=== Port holders (host) ==="
for port in 3000 9090; do
  if ss -tlnp 2>/dev/null | grep -q ":$port "; then echo "  PORT $port still bound"; else echo "  OK: $port free"; fi
done

echo "=== Docker networks ==="
if docker network ls --format '{{.Name}}' | grep -q sentry-net; then
  echo "  sentry-net exists (normal — recreated by compose)"
fi

echo "=== Leftover volumes (should PERSIST, not be deleted) ==="
docker volume ls --format '{{.Name}}' | grep -E "ollama|grafana|prometheus" | sed 's/^/  keep: /'

echo
if [ -z "$running" ]; then echo "READY for ./start.sh"; else echo "NOT clean — run: docker compose -f compose/docker-compose.yml down"; fi
