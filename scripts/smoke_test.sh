#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-localhost}"
BASE="http://$HOST"

echo "=== Smoke Tests for $HOST ==="

check() {
  local label="$1" url="$2" expected="$3"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" || echo "000")
  if [ "$status" = "$expected" ]; then
    echo "  ✓ $label ($status)"
  else
    echo "  ✗ $label  (expected $expected, got $status)"
    return 1
  fi
}

check "nginx health"     "$BASE/nginx-health"    "200"
check "gateway health"   "$BASE/health"          "200"
check "prometheus"       "$BASE:9090/-/healthy"  "200"
check "grafana"          "$BASE:3000/api/health" "200"

echo ""
echo "=== Gateway API round-trip ==="
API_KEY="${API_KEY:-test-key}"
RESP=$(curl -s -X POST "$BASE/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "say ok"}],
    "max_tokens": 10
  }' --max-time 30 || echo '{"error":"timeout"}')
echo "$RESP" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'error' in data:
    print('  ✗', data['error'])
    sys.exit(1)
content = data['choices'][0]['message']['content']
print('  ✓ Response:', content.strip())
"
echo "=== All smoke tests passed ==="
