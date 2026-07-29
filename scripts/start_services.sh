#!/bin/bash
cd /home/elaref/research/RAGIN

export OPENROUTER_API_KEY=sk-or-v1-REPLACED_OPENROUTER_KEY
export API_KEY=ragin-test-key-2024
export REDIS_URL=redis://localhost:6379/0
export RAGIN_LOG_LEVEL=INFO
export GATEWAY_URL=http://localhost:8080

echo "[$(date)] Starting RAGIN services..."

# Kill any existing instances
pkill -f "ragin.server" 2>/dev/null || true
sleep 1

# Start Chrollo (port 8081)
python3 -m ragin.server --component chrollo --port 8081 &
CHROLLO_PID=$!
echo "Chrollo started: PID=$CHROLLO_PID"

# Wait for Chrollo to initialize
sleep 2

# Start Don (port 8082)
python3 -m ragin.server --component don --port 8082 &
DON_PID=$!
echo "Don started: PID=$DON_PID"

# Wait for Don to initialize
sleep 2

# Start Hisoka (port 8083)
python3 -m ragin.server --component hisoka --port 8083 &
HISOKA_PID=$!
echo "Hisoka started: PID=$HISOKA_PID"

sleep 2

echo ""
echo "All services started. PIDs: Chrollo=$CHROLLO_PID Don=$DON_PID Hisoka=$HISOKA_PID"
echo "PIDs written to logs/pids.txt"

echo "$CHROLLO_PID" > logs/pids.txt
echo "$DON_PID" >> logs/pids.txt
echo "$HISOKA_PID" >> logs/pids.txt

# Wait for background processes
wait
