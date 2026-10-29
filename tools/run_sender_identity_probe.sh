#!/usr/bin/env bash
set -eo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <mediator_test_node_PID>" >&2
    exit 1
fi

PID="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! kill -0 "$PID" 2>/dev/null; then
    echo "error: PID $PID is not running" >&2
    exit 1
fi

exec sudo bpftrace -p "$PID" "$SCRIPT_DIR/sender_identity_probe.bt"
