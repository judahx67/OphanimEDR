#!/bin/bash
# Enroll this Ubuntu endpoint with the Wazuh manager, start the agent, then
# generate light filesystem activity so the manager produces real-time FIM
# alerts — a self-evident "monitored endpoint" demo.
set -e

OSSEC=/var/ossec
CONF=$OSSEC/etc/ossec.conf
MANAGER="${WAZUH_MANAGER:-wazuh-manager}"
NAME="${WAZUH_AGENT_NAME:-ubuntu-endpoint}"
WATCH_DIR=/monitor

echo "[endpoint] manager=$MANAGER name=$NAME"
mkdir -p "$WATCH_DIR"

# Real-time FIM on a dedicated directory with a fast periodic scan, so file
# changes surface as alerts within seconds instead of the 12h default.
if ! grep -q "$WATCH_DIR" "$CONF"; then
  sed -i "s#<syscheck>#<syscheck>\n    <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">$WATCH_DIR</directories>#" "$CONF"
  sed -i "0,#<frequency>.*</frequency>#s##<frequency>120</frequency>#" "$CONF"
fi

# Point the agent at the manager (idempotent — install already baked it in).
sed -i "s#<address>.*</address>#<address>$MANAGER</address>#" "$CONF"

# Enroll. authd on the manager may not be ready the instant we boot, so retry.
for i in $(seq 1 30); do
  if "$OSSEC/bin/agent-auth" -m "$MANAGER" -A "$NAME" 2>&1 | tee /tmp/enroll.log | grep -q "Valid key"; then
    echo "[endpoint] enrolled with $MANAGER"; break
  fi
  echo "[endpoint] enrollment attempt $i failed, retrying in 5s..."; sleep 5
done

"$OSSEC/bin/wazuh-control" start
sleep 5
"$OSSEC/bin/wazuh-control" status || true

echo "[endpoint] generating monitored activity in $WATCH_DIR ..."
# Background activity generator: create/modify/delete files the manager will
# flag via FIM, so alerts.json keeps flowing for the demo.
(
  n=0
  while true; do
    n=$((n + 1))
    echo "event $n at $(date -u +%FT%TZ)" > "$WATCH_DIR/file_$((n % 5)).txt"
    if [ $((n % 5)) -eq 0 ]; then rm -f "$WATCH_DIR/stale_$n.txt" 2>/dev/null || true; fi
    sleep 20
  done
) &

# Keep the container in the foreground tailing the agent log.
exec tail -F "$OSSEC/logs/ossec.log"
