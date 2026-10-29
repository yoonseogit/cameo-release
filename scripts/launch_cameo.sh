#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CAMEO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

MANIFEST="${CAMEO_ROOT}/policies/baseline/runtime_manifest.yaml"
POLICY="${CAMEO_ROOT}/policies/baseline/enforcement_policy.yaml"
TRACKER="${CAMEO_ROOT}/provenance_tracker/provenance_tracker"
MEDIATOR="${CAMEO_ROOT}/mediator/build/trusted_mediator"
GUARD="${CAMEO_ROOT}/kernel_bypass_guard/kernel_bypass_guard"
DOMAIN_ID=20
TARGET_TOPIC=""
READY_TIMEOUT=15
LOG_DIR="${CAMEO_ROOT}/run/log"
TARGET=()

tracker_pid=""
mediator_pid=""
guard_pid=""
target_pid=""
cleanup_started=0

usage() {
    cat <<EOF
Usage:
  sudo $0 [options] -- <target-binary> [target-args...]

Options:
  --manifest PATH     Runtime identity manifest (default: ${MANIFEST})
  --policy PATH       Enforcement allowlist (default: ${POLICY})
  --tracker PATH      Provenance tracker executable
  --mediator PATH     Trusted mediator executable
  --guard PATH        Kernel bypass guard executable
  --domain ID         Protected/external DDS domain (default: ${DOMAIN_ID})
  --target-topic NAME Mediator target ROS topic (required, e.g. /validated_msg)
  --timeout SECONDS   Readiness timeout (default: ${READY_TIMEOUT})
  --log-dir PATH      Runtime log directory (default: ${LOG_DIR})
  -h, --help          Show this help

The target is created in a stopped state, registered with the bypass guard,
and resumed only after all security modules are ready.
EOF
}

die() {
    echo "[LAUNCHER_ERROR] $*" >&2
    exit 1
}

is_running() {
    local pid="$1"
    [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

stop_process() {
    local name="$1"
    local pid="$2"

    if is_running "${pid}"; then
        echo "[STOP] ${name} pid=${pid}"
        kill -TERM "${pid}" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?

    if (( cleanup_started )); then
        return
    fi
    cleanup_started=1
    trap - EXIT INT TERM

    # Stop consumers and the untrusted target before removing provenance state.
    stop_process "target" "${target_pid}"
    stop_process "kernel_bypass_guard" "${guard_pid}"
    stop_process "trusted_mediator" "${mediator_pid}"
    stop_process "provenance_tracker" "${tracker_pid}"

    local deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        if ! is_running "${target_pid}" &&
           ! is_running "${guard_pid}" &&
           ! is_running "${mediator_pid}" &&
           ! is_running "${tracker_pid}"; then
            break
        fi
        sleep 0.1
    done

    for pid in "${target_pid}" "${guard_pid}" "${mediator_pid}" "${tracker_pid}"; do
        if is_running "${pid}"; then
            kill -KILL "${pid}" 2>/dev/null || true
        fi
        if [[ -n "${pid}" ]]; then
            wait "${pid}" 2>/dev/null || true
        fi
    done

    echo "[STOPPED] CAMEO runtime (logs: ${LOG_DIR})"
    exit "${status}"
}

wait_for_log() {
    local name="$1"
    local pid="$2"
    local file="$3"
    local pattern="$4"
    local deadline=$((SECONDS + READY_TIMEOUT))

    while (( SECONDS < deadline )); do
        if grep -Fq -- "${pattern}" "${file}" 2>/dev/null; then
            echo "[READY] ${name} pid=${pid}"
            return 0
        fi
        if ! is_running "${pid}"; then
            echo "[LAUNCHER_ERROR] ${name} exited during initialization" >&2
            tail -n 30 "${file}" >&2 || true
            return 1
        fi
        sleep 0.1
    done

    echo "[LAUNCHER_ERROR] ${name} readiness timeout (${READY_TIMEOUT}s)" >&2
    tail -n 30 "${file}" >&2 || true
    return 1
}

while (($#)); do
    case "$1" in
        --manifest) (($# >= 2)) || die "--manifest requires a path"; MANIFEST="$2"; shift 2 ;;
        --policy)   (($# >= 2)) || die "--policy requires a path"; POLICY="$2"; shift 2 ;;
        --tracker)  (($# >= 2)) || die "--tracker requires a path"; TRACKER="$2"; shift 2 ;;
        --mediator) (($# >= 2)) || die "--mediator requires a path"; MEDIATOR="$2"; shift 2 ;;
        --guard)    (($# >= 2)) || die "--guard requires a path"; GUARD="$2"; shift 2 ;;
        --domain)   (($# >= 2)) || die "--domain requires an ID"; DOMAIN_ID="$2"; shift 2 ;;
        --target-topic) (($# >= 2)) || die "--target-topic requires a ROS topic"; TARGET_TOPIC="$2"; shift 2 ;;
        --timeout)  (($# >= 2)) || die "--timeout requires seconds"; READY_TIMEOUT="$2"; shift 2 ;;
        --log-dir)  (($# >= 2)) || die "--log-dir requires a path"; LOG_DIR="$2"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        --)         shift; TARGET=("$@"); break ;;
        *)          die "unknown option: $1 (place the target command after --)" ;;
    esac
done

(( EUID == 0 )) || die "run as root (eBPF, LSM, and bpffs access are required)"
((${#TARGET[@]} > 0)) || die "target command is required after --"
[[ "${DOMAIN_ID}" =~ ^[0-9]+$ ]] || die "domain must be a non-negative integer"
[[ -n "${TARGET_TOPIC}" ]] || die "--target-topic is required"
[[ "${READY_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || die "timeout must be a positive integer"

for path in "${MANIFEST}" "${POLICY}" "${TRACKER}" "${MEDIATOR}" "${GUARD}" "${TARGET[0]}"; do
    [[ -e "${path}" ]] || die "not found: ${path}"
done
for executable in "${TRACKER}" "${MEDIATOR}" "${GUARD}" "${TARGET[0]}"; do
    [[ -x "${executable}" ]] || die "not executable: ${executable}"
done
[[ -d /sys/fs/bpf ]] || die "bpffs mount point is unavailable: /sys/fs/bpf"

mkdir -p -- "${LOG_DIR}"
: >"${LOG_DIR}/tracker.log"
: >"${LOG_DIR}/mediator.log"
: >"${LOG_DIR}/guard.log"
: >"${LOG_DIR}/target.log"

trap cleanup EXIT INT TERM

echo "[START] provenance_tracker"
stdbuf -oL -eL "${TRACKER}" "${MANIFEST}" "${TARGET[0]}" \
    >"${LOG_DIR}/tracker.log" 2>&1 &
tracker_pid=$!
wait_for_log "provenance_tracker" "${tracker_pid}" "${LOG_DIR}/tracker.log" \
    "Press Ctrl+C to stop."

echo "[START] trusted_mediator"
stdbuf -oL -eL "${MEDIATOR}" "${MANIFEST}" "${POLICY}" \
    --target-topic "${TARGET_TOPIC}" \
    >"${LOG_DIR}/mediator.log" 2>&1 &
mediator_pid=$!
wait_for_log "trusted_mediator" "${mediator_pid}" "${LOG_DIR}/mediator.log" \
    "[READY] Waiting for target ROS 2 DDS Writer discovery..."

# The shell stops itself before exec, retaining the same PID across exec.
echo "[PREPARE] target (stopped until guard is active)"
bash -c 'kill -STOP "$BASHPID"; exec "$@"' bash "${TARGET[@]}" \
    >"${LOG_DIR}/target.log" 2>&1 &
target_pid=$!

target_state=""
for ((i = 0; i < 100; ++i)); do
    is_running "${target_pid}" || die "target exited before guard registration"
    target_state="$(awk '{print $3}' "/proc/${target_pid}/stat" 2>/dev/null || true)"
    [[ "${target_state}" == "T" || "${target_state}" == "t" ]] && break
    sleep 0.05
done
[[ "${target_state}" == "T" || "${target_state}" == "t" ]] || die "could not stop target before guard registration"

echo "[START] kernel_bypass_guard target_pid=${target_pid} mediator_pid=${mediator_pid}"
stdbuf -oL -eL "${GUARD}" "${target_pid}" "${mediator_pid}" "${DOMAIN_ID}" \
    >"${LOG_DIR}/guard.log" 2>&1 &
guard_pid=$!
wait_for_log "kernel_bypass_guard" "${guard_pid}" "${LOG_DIR}/guard.log" \
    "Enforcement      : ENABLED"

kill -CONT "${target_pid}"
echo "[RUNNING] target pid=${target_pid}"
echo "[RUNNING] CAMEO security runtime; press Ctrl+C to stop"

set +e
wait "${target_pid}"
target_status=$?
set -e
echo "[TARGET_EXIT] status=${target_status}"
exit "${target_status}"
