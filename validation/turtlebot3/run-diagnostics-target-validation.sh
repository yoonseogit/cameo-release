#!/usr/bin/env bash
set -Eeuo pipefail

readonly ROOT=/home/cclab/01Project/CAMEO
readonly V=${ROOT}/validation/turtlebot3
readonly RUN=${V}/runtime/diagnostics-target-$(date +%Y%m%d-%H%M%S)
readonly MAN=${V}/policies/runtime_manifest.yaml
readonly POL=${V}/policies/enforcement_policy.yaml
readonly TARGET=${ROOT}/ros_ws/install/callback_security_demo_pkg/lib/callback_security_demo_pkg/demo_node
readonly LAUNCHER=${ROOT}/scripts/launch_cameo.sh
readonly COMPONENT_LOGS=${RUN}/components
launcher_pid=""
echo_pid=""
cleanup_started=0

log() { printf '[DIAGNOSTICS_VALIDATION] %s\n' "$*" | tee -a "${RUN}/driver.log"; }
fail() { log "FAIL: $*"; printf 'FAIL: %s\n' "$*" >"${RUN}/result.txt"; exit 1; }
is_running() { [[ -n "${1:-}" ]] && kill -0 "$1" 2>/dev/null; }
cleanup() {
  local status=$?
  (( cleanup_started == 0 )) || return
  cleanup_started=1
  trap - EXIT INT TERM
  if is_running "${echo_pid}"; then kill -INT "${echo_pid}" 2>/dev/null || true; fi
  if is_running "${launcher_pid}"; then
    kill -INT "${launcher_pid}" 2>/dev/null || true
    for _ in $(seq 1 50); do is_running "${launcher_pid}" || break; sleep 0.1; done
  fi
  if is_running "${launcher_pid}"; then kill -TERM "${launcher_pid}" 2>/dev/null || true; fi
  for _ in $(seq 1 30); do is_running "${launcher_pid}" || break; sleep 0.1; done
  if is_running "${launcher_pid}"; then kill -KILL "${launcher_pid}" 2>/dev/null || true; fi
  [[ -n "${echo_pid}" ]] && wait "${echo_pid}" 2>/dev/null || true
  [[ -n "${launcher_pid}" ]] && wait "${launcher_pid}" 2>/dev/null || true
  log "cleanup complete"
  exit "$status"
}

[[ ${EUID} -eq 0 ]] || { echo "Run with sudo: sudo ${ROOT}/validation/turtlebot3/run-diagnostics-target-validation.sh" >&2; exit 2; }
cd "${ROOT}"
mkdir -p "${RUN}" "${COMPONENT_LOGS}"
touch "${RUN}/driver.log"
trap cleanup EXIT INT TERM

for f in "${MAN}" "${POL}" "${TARGET}" "${LAUNCHER}" \
  "${ROOT}/provenance_tracker/provenance_tracker" \
  "${ROOT}/mediator/build/trusted_mediator" \
  "${ROOT}/kernel_bypass_guard/kernel_bypass_guard"; do
  [[ -e "$f" ]] || fail "missing required file: $f"
done

grep -Eq 'ros_name: "/diagnostics"' "${MAN}" || fail "manifest lacks /diagnostics"
grep -Eq 'dds_name: "rt/diagnostics"' "${MAN}" || fail "manifest lacks rt/diagnostics"
if [[ -e /sys/fs/bpf/ros2_security ]]; then
  if find /sys/fs/bpf/ros2_security -mindepth 1 -print -quit | grep -q .; then
    fail "pre-existing non-empty /sys/fs/bpf/ros2_security found"
  fi
  rmdir /sys/fs/bpf/ros2_security
  log "removed empty ros2_security directory left by prior validation"
fi
if pgrep -f '[/]provenance_tracker( |$)|[/]trusted_mediator( |$)|[/]kernel_bypass_guard( |$)' >/dev/null; then
  fail "pre-existing CAMEO runtime process found"
fi
bpftool prog show >"${RUN}/bpf-programs-before.txt"
bpftool map show >"${RUN}/bpf-maps-before.txt"

set +u
source "${ROOT}/scripts/D10.sh" >>"${RUN}/driver.log" 2>&1
set -u
export ROS_LOG_DIR="${RUN}/ros-logs-domain10"
mkdir -p "${ROS_LOG_DIR}"

log "starting same mediator binary with target /diagnostics"
"${LAUNCHER}" \
  --manifest "${MAN}" --policy "${POL}" --domain 20 \
  --target-topic /diagnostics --timeout 25 \
  --log-dir "${COMPONENT_LOGS}" -- "${TARGET}" \
  >"${RUN}/launcher.log" 2>&1 &
launcher_pid=$!
for _ in $(seq 1 300); do
  grep -Fq '[RUNNING] CAMEO security runtime' "${RUN}/launcher.log" 2>/dev/null && break
  is_running "${launcher_pid}" || { tail -100 "${RUN}/launcher.log" >&2; fail "launcher exited during initialization"; }
  sleep 0.1
done
grep -Fq '[RUNNING] CAMEO security runtime' "${RUN}/launcher.log" || fail "launcher readiness timeout"
log "launcher ready"
sleep 3

mkdir -p "${RUN}/ros-logs-domain20"
timeout --signal=INT --kill-after=2s 30s bash -c \
  'set +u; source "$1" >/dev/null; set -u; export ROS_LOG_DIR="$2"; ros2 topic echo --once /diagnostics std_msgs/msg/String' \
  bash "${ROOT}/scripts/D20.sh" "${RUN}/ros-logs-domain20" >"${RUN}/domain20-diagnostics.txt" 2>&1 &
echo_pid=$!
sleep 12
timeout 12s ros2 topic pub --once /input_A std_msgs/msg/String "{data: 'CAMEO-DIAGNOSTICS'}" >"${RUN}/publish.log" 2>&1
set +e; wait "${echo_pid}"; echo_status=$?; set -e
echo_pid=""
[[ ${echo_status} -eq 0 ]] || fail "Domain 20 diagnostics subscriber timed out (status ${echo_status})"
grep -Eq 'diagnostic:A:CAMEO-DIAGNOSTICS' "${RUN}/domain20-diagnostics.txt" || fail "expected diagnostics payload not observed"
grep -Eq 'Target ROS Topic: /diagnostics' "${COMPONENT_LOGS}/mediator.log" || fail "Mediator did not select ROS diagnostics"
grep -Eq 'Target DDS Topic: rt/diagnostics' "${COMPONENT_LOGS}/mediator.log" || fail "Mediator did not select DDS diagnostics"
grep -Eq 'Target Topic ID : 1' "${COMPONENT_LOGS}/mediator.log" || fail "Mediator did not select TopicID 1"
grep -Eq '\[PROVENANCE_HIT\]' "${COMPONENT_LOGS}/mediator.log" || fail "missing PROVENANCE_HIT"
grep -Eq 'callback_instance_id=1' "${COMPONENT_LOGS}/mediator.log" || fail "missing CallbackInstanceID 1"
grep -Eq 'ALLOWLIST_HIT' "${COMPONENT_LOGS}/mediator.log" || fail "missing ALLOWLIST_HIT"
grep -Eq '\[MEDIATOR_TX\]' "${COMPONENT_LOGS}/mediator.log" || fail "missing MEDIATOR_TX"
grep -Eq 'Enforcement      : ENABLED' "${COMPONENT_LOGS}/guard.log" || fail "Guard did not become ready"

printf 'PASS\n' >"${RUN}/result.txt"
log "PASS: /diagnostics -> rt/diagnostics -> TopicID 1; Callback A allowed and observed in Domain 20"
log "logs: ${RUN}"
