#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${PROJECT_ROOT}/scripts/D10.sh"

set -u

echo "[CONCURRENT_TRIGGER] publishing /input_A and /input_B concurrently"

ros2 topic pub --once \
  /input_A \
  std_msgs/msg/String \
  "{data: 'CONCURRENT-A'}" &
PID_A=$!

ros2 topic pub --once \
  /input_B \
  std_msgs/msg/String \
  "{data: 'CONCURRENT-B'}" &
PID_B=$!

wait "${PID_A}"
wait "${PID_B}"

echo "[CONCURRENT_TRIGGER] done"
