# CAMEO

**Callback-Aware Mediation and Enforcement Overlay** — a ROS 2 research prototype for callback-instance-aware cross-domain topic authorization.

CAMEO identifies the callback responsible for a DDS sample, checks its callback-to-topic authorization policy in a trusted mediator, and blocks direct sends that bypass the mediated path to a protected DDS domain.

## Architecture

```text
ROS 2 source code
    └── Policy Generator (Clang AST)
        ├── Runtime Manifest (CallbackInstanceID / TopicID)
        └── Enforcement Policy (callback-topic allowlist)

Untrusted ROS 2 Node  →  Provenance Tracker (eBPF)
        │                       │
        └── DDS sample ─────────┴→ Trusted Mediator ─→ Protected DDS Domain
                    │                    │
                    └── Kernel Bypass Guard (eBPF LSM): direct-send prevention
```

The components implement:

- **Policy Generator** — extracts callback/topic candidates from C++ source code and produces a runtime manifest and callback-topic allowlist.
- **Provenance Tracker** — observes callback execution and DDS/RTPS publication paths to associate samples with callback instances.
- **Trusted Mediator** — checks sample provenance and the allowlist before forwarding to the protected DDS domain.
- **Kernel Bypass Guard** — restricts direct DDS/UDP transmission to the protected domain so that a target process cannot trivially bypass mediation.

## Repository layout

| Directory | Contents |
| --- | --- |
| `policy_generator/` | Clang AST-based static analysis and policy compilation |
| `provenance_tracker/` | eBPF provenance instrumentation and Go loader |
| `mediator/` | Fast DDS-based trusted mediator |
| `kernel_bypass_guard/` | eBPF LSM bypass protection and Go loader |
| `policies/` | Example runtime manifest and enforcement allowlist |
| `ros_ws/src/` | ROS 2 demonstration and evaluation nodes |
| `scripts/` | Launcher and experiment helpers |
| `tools/` | Fast DDS layout and sender-identity probes |
| `validation/turtlebot3/` | TurtleBot3 setup and evaluation support files |

## Environment

This prototype targets **Linux ARM64**, **ROS 2 Jazzy**, **Fast DDS 2.14.6**, **Clang/LLVM**, **Go**, and a Linux kernel supporting **BTF, eBPF uprobes, bpffs, and BPF LSM**. Root privileges are required for the eBPF security components.

The tracker contains Fast DDS/ARM64 ABI-specific offsets and assumptions; adapt these to the deployment environment before use.

## Build

Source ROS 2 and install the system dependencies appropriate to your environment, including Fast DDS, Fast CDR, yaml-cpp, LLVM/Clang development packages, Go, and libbpf tooling.

```bash
source /opt/ros/jazzy/setup.bash

cmake -S policy_generator -B policy_generator/build
cmake --build policy_generator/build -j

cmake -S mediator -B mediator/build
cmake --build mediator/build -j

(cd provenance_tracker && go build -o provenance_tracker .)
(cd kernel_bypass_guard && go build -o kernel_bypass_guard .)

cd ros_ws
colcon build --symlink-install
```

The tracked `*_arm64_bpfel.o` artifacts correspond to an ARM64 build. If regenerating eBPF artifacts for a different kernel, generate each `bpf/vmlinux.h` from that kernel's BTF:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > provenance_tracker/bpf/vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > kernel_bypass_guard/bpf/vmlinux.h
```

## Policy and execution

The policy compiler emits two related YAML artifacts: a **runtime manifest** with callback instance and topic identities, and an **enforcement policy** containing allowed pairs. Both use a matching `manifest_id`.

```bash
./policy_generator/build/policy_generator \
  --manifest-output runtime_manifest.yaml \
  --output enforcement_policy.yaml \
  <source-files...> -- <clang-compilation-options...>
```

The launcher expects explicit policy artifacts, a target executable, and a target topic. Example invocation pattern:

```bash
sudo ./scripts/launch_cameo.sh \
  --manifest runtime_manifest.yaml \
  --policy enforcement_policy.yaml \
  --target-topic /validated_msg \
  -- /path/to/target_executable
```

The protected DDS domain and target/topic settings must match the test deployment. `scripts/launch_cameo.sh --help` documents additional options. The sample YAML files in `policies/` illustrate the expected formats.

## Evaluation scope

The accompanying CISC-W'26 paper evaluates callback-level authorization, policy generation, protected-domain direct-send bypass prevention, and cross-domain performance against a baseline relay and a DDS Security router.

## Scope and license

CAMEO is a research prototype designed around a specific ROS 2/Fast DDS stack. It is not a general-purpose production security product. The mediator uses a selected target topic, and the eBPF tracker depends on specific runtime layouts.

No project-wide license is granted by this repository. Package-local third-party licenses remain applicable.
