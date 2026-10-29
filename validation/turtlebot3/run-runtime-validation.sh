#!/usr/bin/env bash
set -Eeuo pipefail

readonly ROOT=/home/cclab/01Project/CAMEO
readonly V=${ROOT}/validation/turtlebot3
readonly RUN=${V}/runtime/root-validation-$(date +%Y%m%d-%H%M%S)
readonly MAN=${V}/policies/runtime_manifest.yaml
readonly POL=${V}/policies/enforcement_policy.yaml
readonly TARGET=${ROOT}/ros_ws/install/callback_security_demo_pkg/lib/callback_security_demo_pkg/demo_node
readonly LAUNCHER=${ROOT}/scripts/launch_cameo.sh
readonly COMPONENT_LOGS=${RUN}/components
launcher_pid=""
echo_pid=""
cleanup_started=0

log() { printf '[RUNTIME_VALIDATION] %s\n' "$*" | tee -a "${RUN}/driver.log"; }
fail() { log "FAIL: $*"; printf 'FAIL: %s\n' "$*" >"${RUN}/result.txt"; exit 1; }
is_running() { [[ -n "${1:-}" ]] && kill -0 "$1" 2>/dev/null; }
cleanup() {
  local status=$?
  (( cleanup_started == 0 )) || return
  cleanup_started=1
  trap - EXIT INT TERM
  if is_running "${launcher_pid}"; then
    kill -INT "${launcher_pid}" 2>/dev/null || true
    for _ in $(seq 1 50); do is_running "${launcher_pid}" || break; sleep 0.1; done
  fi
  if is_running "${launcher_pid}"; then kill -TERM "${launcher_pid}" 2>/dev/null || true; fi
  for _ in $(seq 1 30); do is_running "${launcher_pid}" || break; sleep 0.1; done
  if is_running "${launcher_pid}"; then kill -KILL "${launcher_pid}" 2>/dev/null || true; fi
  [[ -n "${launcher_pid}" ]] && wait "${launcher_pid}" 2>/dev/null || true
  log "cleanup complete"
  exit "$status"
}

[[ ${EUID} -eq 0 ]] || { echo "Run with sudo: sudo ${ROOT}/validation/turtlebot3/run-runtime-validation.sh" >&2; exit 2; }
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

if [[ -e /sys/fs/bpf/ros2_security ]]; then
  if find /sys/fs/bpf/ros2_security -mindepth 1 -print -quit | grep -q .; then
    fail "pre-existing non-empty /sys/fs/bpf/ros2_security found; refusing to alter existing BPF state"
  fi
  rmdir /sys/fs/bpf/ros2_security
  log "removed empty ros2_security directory left by the prior validation run"
fi
if pgrep -f '[/]provenance_tracker( |$)' >/dev/null || pgrep -f '[/]trusted_mediator( |$)' >/dev/null || pgrep -f '[/]kernel_bypass_guard( |$)' >/dev/null; then
  fail "pre-existing CAMEO runtime process found; refusing to interfere"
fi
if pgrep -f '[t]urtlebot3_node|[r]os2_control_node|[t]eleop_twist|[n]av2_' >/dev/null; then
  log "robot-control process detected; validated_msg-only test continues; cmd_vel remains prohibited"
fi
bpftool prog show >"${RUN}/bpf-programs-before.txt"
bpftool map show >"${RUN}/bpf-maps-before.txt"

set +u
source "${ROOT}/scripts/D10.sh" >>"${RUN}/driver.log" 2>&1
set -u
export ROS_LOG_DIR="${RUN}/ros-logs-domain10"
mkdir -p "${ROS_LOG_DIR}"

log "starting launcher with target ELF ${TARGET}"
"${LAUNCHER}" \
  --manifest "${MAN}" --policy "${POL}" --domain 20 \
  --target-topic /validated_msg --timeout 25 \
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

start_echo() {
  local output=$1
  mkdir -p "${RUN}/ros-logs-domain20"
  timeout --signal=INT --kill-after=2s 30s bash -c \
    'set +u; source "$1" >/dev/null; set -u; export ROS_LOG_DIR="$2"; ros2 topic echo --once /validated_msg std_msgs/msg/String' \
    bash "${ROOT}/scripts/D20.sh" "${RUN}/ros-logs-domain20" >"${output}" 2>&1 &
  echo_pid=$!
}
publish_d10() {
  local topic=$1 payload=$2
  timeout 12s ros2 topic pub --once "$topic" std_msgs/msg/String "{data: '${payload}'}" >>"${RUN}/publish.log" 2>&1
}

start_echo "${RUN}/domain20-callback-a.txt"; a_echo=${echo_pid}
sleep 12
publish_d10 /input_A CAMEO-A
set +e; wait "${a_echo}"; a_status=$?; set -e
if [[ ${a_status} -ne 124 ]] || grep -Eq 'tampered:A:CAMEO-A' "${RUN}/domain20-callback-a.txt"; then
  fail "Callback A unauthorized validated_msg reached Domain 20"
fi
log "Callback A unauthorized validated_msg denied"

start_echo "${RUN}/domain20-callback-b.txt"; b_echo=${echo_pid}
sleep 12
publish_d10 /input_B CAMEO-B
set +e; wait "${b_echo}"; b_status=$?; set -e
[[ ${b_status} -eq 0 ]] || fail "Callback B subscriber timed out (status ${b_status})"
grep -Eq 'validated:B:CAMEO-B' "${RUN}/domain20-callback-b.txt" || fail "Callback B expected payload not observed"
log "Callback B allowlisted validated_msg observed"

start_echo "${RUN}/domain20-provenance-miss.txt"; miss_echo=${echo_pid}
sleep 12
timeout 12s ros2 topic pub --once /validated_msg std_msgs/msg/String "{data: 'CAMEO-PROVENANCE-MISS'}" >>"${RUN}/publish.log" 2>&1
set +e; wait "${miss_echo}"; miss_status=$?; set -e
if [[ ${miss_status} -ne 124 ]] || grep -Eq 'CAMEO-PROVENANCE-MISS' "${RUN}/domain20-provenance-miss.txt"; then
  fail "untracked provenance-miss sample reached Domain 20"
fi
if grep -Eq '\[PROVENANCE_MISS\]' "${COMPONENT_LOGS}/mediator.log"; then
  log "untracked sample rejected by provenance-map miss"
elif grep -Eq '\[RX_SKIP\].*|reason=non_target_writer' "${COMPONENT_LOGS}/mediator.log"; then
  log "untracked sample rejected earlier by target-writer binding"
else
  fail "no fail-closed evidence for untracked sample"
fi
log "provenance miss failed closed"

grep -Eq '\[TOPIC_REGISTRY\].*ros=/validated_msg.*dds=rt/validated_msg' "${COMPONENT_LOGS}/tracker.log" || fail "missing runtime TOPIC_REGISTRY for validated_msg"
grep -Eq '\[PROVENANCE_HIT\]' "${COMPONENT_LOGS}/mediator.log" || fail "missing PROVENANCE_HIT"
grep -Eq 'ALLOWLIST_HIT' "${COMPONENT_LOGS}/mediator.log" || fail "missing ALLOWLIST_HIT"
grep -Eq 'NOT_IN_ALLOWLIST' "${COMPONENT_LOGS}/mediator.log" || fail "missing NOT_IN_ALLOWLIST"
grep -Eq 'Enforcement      : ENABLED' "${COMPONENT_LOGS}/guard.log" || fail "Guard did not become ready"

printf 'PASS\n' >"${RUN}/result.txt"
log "PASS: A deny, B allow, provenance miss fail-closed, Guard ready"
log "logs: ${RUN}"
