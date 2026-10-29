# CAMEO TurtleBot3 Validation Report

Date: 2026-08-29 (Asia/Seoul)
Repository: `/home/cclab/01Project/CAMEO`
Branch: `feature/policy-compiler-generalization`
HEAD: `e42f46ecc4c278382906d0937d3436ca684d8655`

## 작업 결과

| 항목 | 상태 | 결과 |
|---|---|---|
| 실행 위치 | PASS | `turtlebot3`, user `cclab`, `aarch64`, kernel `6.8.0-1063-raspi` |
| Git/branch | PASS | feature branch/known HEAD 일치. 로컬 remote-tracking ref와 ahead/behind `0/0` |
| 원격 refresh | BLOCKED | `git fetch origin`: HTTPS credential 없음 |
| TurtleBot3용 `vmlinux.h` | PASS | 두 모듈 각각 BTF에서 안전 재생성, 114791 lines, 2458612 bytes |
| PT `go generate` | PASS | ARM64 bpf2go binding/object 재생성 |
| PT build | PASS | aarch64 userspace ELF 생성 |
| `topic_registry_config` binding | PASS | MapSpec/Map 필드 확인 |
| PG build | PASS | LLVM 18.1.3, LLVM_DIR `/usr/lib/llvm-18/cmake`, Clang_DIR `/usr/lib/cmake/clang-18` |
| Mediator build | PASS | aarch64 ELF; Fast DDS, Fast CDR, yaml-cpp 링크 확인 |
| `--target-topic` | PASS | 필수 usage 및 manifest 기반 선택 코드/negative test 확인 |
| 고정 `/validated_msg` 제거 | PASS | Mediator에 고정 상수/기본값 없음. 고정 상수는 bypass test fixture에만 존재 |
| Guard build | PASS | aarch64 userspace ELF + eBPF ELF; launcher 기대 경로 일치 |
| ROS 2 target build | PASS | 4 packages, 실제 ELF 및 compile databases 확인 |
| Manifest/Policy 생성 | PASS | benign snapshot과 실제 compile options 사용 |
| manifest_id 정합성 | PASS | 양쪽 `f126bae00d884890` |
| CallbackInstanceID 정합성 | PASS | 1, 2; non-zero/unique/registered |
| TopicID 정합성 | PASS | 1, 2; non-zero/unique/registered |
| Topic normalization | PASS | `/diagnostics`→`rt/diagnostics`, `/validated_msg`→`rt/validated_msg` |
| Duplicate input topic fail-closed | PASS | exit non-zero, `DUPLICATE_INPUT_TOPIC`, 산출물 미생성 |
| PT topic registry | BLOCKED | 코드/binding은 확인. root 부재로 map load 및 `[TOPIC_REGISTRY]` runtime 로그 미검증 |
| Launcher | PASS | `bash -n scripts/launch_cameo.sh` |
| PT/Mediator initialization | BLOCKED | Mediator parsing/target/ID fail-closed는 PASS. 전체 init은 BPF map 권한, PT는 memlock rlimit 권한에서 중단 |
| `/validated_msg` 회귀 | BLOCKED | 안전 fixture는 있으나 PT/Guard root load 불가 |
| `/cmd_vel` target 선택 | BLOCKED | manifest와 저장소 fixture에 `/cmd_vel` 없음 |
| TurtleBot3 bringup/속도 발행 | NOT RUN | 안전 원칙에 따라 실행하지 않음 |
| Guard bypass | BLOCKED | fixture/build는 확인했으나 root load 불가 |
| cleanup | PASS | 이번 실행 CAMEO 프로세스 없음; BPF state는 권한 단계 전에 실패해 생성되지 않음 |

## 확인된 구현 사실

### 코드에 구현된 기능

- PG는 동일 normalized input topic의 두 번째 subscription을 산출물 open 전에 거부한다.
- PT는 `instance=1`만 허용하며 `topic_registry_config`를 채우고 `[TOPIC_REGISTRY]`를 출력하는 코드가 있다.
- Mediator는 manifest의 ROS name, DDS name, TopicID를 연결하고 `--target-topic`으로 선택한다.
- Guard는 등록된 untrusted TGID의 IPv4 UDP에만 적용되며 Domain 20은 12400–12649 포트다. 미등록 프로세스와 TCP SSH는 대상이 아니다.
- Go loaders는 defer/close 및 link close로 종료 시 자체 object/link를 정리한다.

### build로 확인된 기능

- PT/Guard userspace: ARM aarch64 ELF.
- PT/Guard BPF objects: eBPF ELF.
- PG/Mediator/ROS executables: ARM aarch64 ELF.
- Mediator: `libfastrtps.so.2.14`, `libfastcdr.so.2`, `libyaml-cpp.so.0.8` 링크.

### runtime에서 확인된 기능

- PG benign 관계 및 duplicate fail-closed.
- Mediator missing target, unknown target, manifest mismatch, unknown identity의 fail-closed.
- 유효 target `/validated_msg` 선택: DDS `rt/validated_msg`, TopicID 2. 이후 provenance map permission에서 fail-closed.

### 검증되지 않은 예상

- PT의 BPF attach, runtime topic registry population, provenance hit/set.
- 실제 ALLOW/DENY 전달 경로와 Guard `BYPASS_DENY`.
- `/cmd_vel` target 전환.

### 명시적 제한

- PT selector는 현재 `instance=1`만 지원한다.
- Mediator는 process당 단일 target topic이다.
- `/cmd_vel` fixture가 저장소에 없다.
- 비대화형 sudo가 없어 privileged runtime은 수행할 수 없다.

## 변경된 파일

1. 작업 전 사용자 변경: 없음(시작 시 working tree clean).
2. 이번 작업 변경: `policy_generator/src/policy_generator.cpp`, `validation/turtlebot3/**`.
3. 자동 생성 파일: 두 `bpf/vmlinux.h`, PT generated Go/BPF object, Guard BPF object. 실행 바이너리/build/install/log는 ignore 경로에 생성.
4. 직접 수정한 소스: PG duplicate-input fail-closed 9 lines.

`vmlinux.h` 변경은 target-kernel-specific 자동 생성물이며 소스 결함이나 자동 commit 대상으로 분류하지 않는다.

## 실패 또는 차단 사항

| 단계 | 명령/첫 오류 | 원인 | 최소 대응/재검증 |
|---|---|---|---|
| 원격 확인 | `git fetch origin` → `fatal: could not read Username for 'https://github.com'` | HTTPS credential 없음 | 기존 local remote ref 확인; HEAD 동일, ahead/behind 0/0. 최신 원격 여부는 미보장 |
| 최초 ROS build | `source /opt/ros/jazzy/setup.bash` → `AMENT_TRACE_SETUP_FILES: unbound variable` | `set -u`와 setup script 충돌 | source 동안 nounset 해제 후 재실행; 4 packages PASS |
| PG/PT 범위 | PG가 instance 2 생성 가능, PT는 instance 1만 허용 | fail-closed 누락 | PG 최소 수정 후 정상/중복 fixture 재검증 PASS |
| YAML 검사 도구 | `ruby: command not found` | Ruby 미설치 | 설치하지 않고 awk/sort 검사로 PASS |
| BPF 상태/runtime | `sudo: a password is required`; PT `remove memlock limit: operation not permitted` | 비대화형 root 권한 없음 | PT/Guard load하지 않음; runtime items BLOCKED |
| Mediator valid init | BPF map open `errno=13 Permission denied` | PT map 미생성/root 권한 없음 | target 선택까지 확인 후 fail-closed; 전체 init BLOCKED |
| `/cmd_vel` | repository search 결과 fixture/topic 없음 | 안전 fixture/manifest 부족 | 임의 노드와 velocity publish를 만들지 않고 BLOCKED |

## 정책 검증 결과

Manifest: `validation/turtlebot3/policies/runtime_manifest.yaml`
Policy: `validation/turtlebot3/policies/enforcement_policy.yaml`
Manifest ID: `f126bae00d884890`

| CallbackInstanceID | selector | TopicID | ROS/DDS topic | allow |
|---:|---|---:|---|---|
| 1 | `/input_A`, instance 1 | 1 | `/diagnostics` / `rt/diagnostics` | yes |
| 2 | `/input_B`, instance 1 | 2 | `/validated_msg` / `rt/validated_msg` | yes |

중복 ID, zero ID, 미등록 allow 참조, 명시적 deny는 없다. TopicID는 정렬된 publisher topic 집합(`/diagnostics`, `/validated_msg`) 순서와 일치한다.

## Git 상태

```text
 M kernel_bypass_guard/bpf/vmlinux.h
 M kernel_bypass_guard/guard_arm64_bpfel.o
 M policy_generator/src/policy_generator.cpp
 M provenance_tracker/bpf/vmlinux.h
 M provenance_tracker/provenance_arm64_bpfel.go
 M provenance_tracker/provenance_arm64_bpfel.o
?? validation/
```

```text
kernel_bypass_guard/bpf/vmlinux.h            | 166984 ++++++++++++------------
kernel_bypass_guard/guard_arm64_bpfel.o      | Bin 41400 -> 41536 bytes
policy_generator/src/policy_generator.cpp    | 9 +
provenance_tracker/bpf/vmlinux.h             | 166984 ++++++++++++------------
provenance_tracker/provenance_arm64_bpfel.go | 14 +
provenance_tracker/provenance_arm64_bpfel.o  | Bin 29872 -> 29624 bytes
6 files changed, 167097 insertions(+), 166894 deletions(-)
```

Changed tracked names:

```text
kernel_bypass_guard/bpf/vmlinux.h
kernel_bypass_guard/guard_arm64_bpfel.o
policy_generator/src/policy_generator.cpp
provenance_tracker/bpf/vmlinux.h
provenance_tracker/provenance_arm64_bpfel.go
provenance_tracker/provenance_arm64_bpfel.o
```

Branch: `feature/policy-compiler-generalization`
Local HEAD: `e42f46ecc4c278382906d0937d3436ca684d8655`
Local remote-tracking HEAD: `e42f46ecc4c278382906d0937d3436ca684d8655`
Ahead/behind: `0/0`

No commit, push, PR, merge performed.

## Privileged runtime validation update

This section supersedes the earlier root-permission BLOCKED statuses.

Validated run: `validation/turtlebot3/runtime/root-validation-20260829-195738/`

| Runtime item | Final status | Evidence |
|---|---|---|
| PT initialization | PASS | BPF map pinned/opened, probes ready, selectors and both `[TOPIC_REGISTRY]` entries logged |
| Mediator initialization | PASS | Domain 10/20 participants, target writer discovery, bridge setup, `[MEDIATOR_READY]` |
| Guard initialization | PASS | Domain 20 UDP 12400–12649, registered target/mediator TGIDs, enforcement enabled |
| Callback A regression | PASS | callback 1/topic 2 provenance hit, `NOT_IN_ALLOWLIST`, `MEDIATOR_DENY`; Domain 20 observer empty |
| Callback B regression | PASS | callback 2/topic 2 provenance hit, `ALLOWLIST_HIT`, `MEDIATOR_TX`; Domain 20 received `validated:B:CAMEO-B` |
| Untracked publisher fail-closed | PASS | second writer ignored, `RX_SKIP reason=non_target_writer`; Domain 20 observer empty |
| Exact `[PROVENANCE_MISS]` branch | NOT RUN | single-target writer binding rejects the foreign writer before provenance-map lookup |
| Guard ON normal Mediator path | PASS | B sample traversed Mediator to Domain 20 while Guard was enabled |
| Direct Guard bypass / `BYPASS_DENY` | BLOCKED | this run did not execute the separate direct Fast DDS bypass target |
| Cleanup | PASS | launcher stopped target, Guard, Mediator and PT; no CAMEO process or visible BPF pin remained |

The runtime driver originally treated absence of the deeper `[PROVENANCE_MISS]` log as failure. Logs show that the foreign writer was rejected earlier by the stricter first-target-writer binding. The driver now accepts either explicit provenance-map miss or evidenced `non_target_writer` rejection, while reporting which path was exercised.

## Second runtime-selected target: `/diagnostics`

Final status: **PASS**

Validated run: `validation/turtlebot3/runtime/diagnostics-target-20260829-204912/`

The same `mediator/build/trusted_mediator` binary and the same manifest/policy bundle were launched with only the runtime argument changed from `--target-topic /validated_msg` to `--target-topic /diagnostics`.

| Check | Result | Evidence |
|---|---|---|
| Runtime ROS target | PASS | `Target ROS Topic: /diagnostics` |
| Runtime DDS target | PASS | `Target DDS Topic: rt/diagnostics` |
| Manifest TopicID | PASS | `Target Topic ID : 1` |
| Provenance | PASS | CallbackInstanceID 1 / TopicID 1 hit |
| Policy | PASS | `ALLOWLIST_HIT` |
| Republish | PASS | `MEDIATOR_TX`, rx=1, tx=1, deny=0 |
| Domain 20 observation | PASS | `data: diagnostic:A:CAMEO-DIAGNOSTICS` |
| Guard ON normal path | PASS | Domain 20 enforcement enabled throughout the transmission |
| Cleanup | PASS | target, Guard, Mediator and PT stopped; no visible CAMEO BPF pin remained |

This demonstrates runtime target-topic generalization without recompilation: `/validated_msg` selected TopicID 2 in the first run, while `/diagnostics` selected TopicID 1 in this run using the same executable.

## Authenticated remote verification update

Final status: **PASS**

An authenticated `git fetch origin` completed successfully after the earlier credential-blocked attempt.

- Local HEAD: `e42f46ecc4c278382906d0937d3436ca684d8655`
- Remote feature HEAD: `e42f46ecc4c278382906d0937d3436ca684d8655`
- Ahead/behind: `0/0`
- `HEAD..origin/feature/policy-compiler-generalization`: empty
- `origin/feature/policy-compiler-generalization..HEAD`: empty

The local branch was synchronized with the current remote feature branch immediately before commit preparation.

## Logical change commit update

The reviewed logical change group was committed locally:

```text
98643ac Fail closed on unsupported duplicate input topics
```

Commit contents:

- `policy_generator/src/policy_generator.cpp`
- `provenance_tracker/provenance_arm64_bpfel.go`
- `provenance_tracker/provenance_arm64_bpfel.o`

At the time of this update the local feature branch is one commit ahead of the authenticated remote feature branch. It has not been pushed.
