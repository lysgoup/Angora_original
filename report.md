# angora_storfuzz 통합 구현 보고서

작성일: 2026-05-08
최종 수정: 2026-05-08 (Bug #6 — DATA_SHM_ENV_VAR envs 누락 수정)
작업 디렉토리: `./Angora_original/`
참조 레포: `./StorFuzz-LibAFL/` (읽기 전용)

---

## 1. 목표 요약

Angora 퍼저 위에 StorFuzz의 데이터 흐름 커버리지 아이디어를 최소 범위로 이식하여,
공정한 실험 비교를 위한 `angora_storfuzz` 바이너리를 새로 생성한다.

- 기존 `angora` 바이너리의 동작은 **한 줄도 변경하지 않는다.**
- 새로운 코드는 Rust 측에서는 `#[cfg(feature = "storfuzz")]`, C/LLVM 측에서는 환경변수 게이트로 격리한다.
- 데이터 커버리지 맵은 브랜치 커버리지 맵과 완전히 독립적인 shmem 세그먼트를 사용한다.

---

## 2. 변경 파일 전체 목록

### 2-1. 신규 생성 (4개)

| 파일 | 설명 |
|------|------|
| `llvm_mode/pass/StorFuzzPass.cc` | StorFuzz 데이터 커버리지 LLVM 11 Legacy PM 패스 |
| `runtime_fast/src/storfuzz_rt.c` | 계측된 바이너리에 링크되는 C 런타임 (shmem attach) |
| `fuzzer/src/data_cov.rs` | Rust 퍼저 측 DataCov 구조체 |
| `tests/storfuzz_sanity.c` | 기능 검증용 sanity test 타깃 |

### 2-2. 수정된 기존 파일 (9개)

| 파일 | 변경 내용 요약 |
|------|---------------|
| `llvm_mode/pass/CMakeLists.txt` | StorFuzzPass 빌드 타깃 추가 |
| `llvm_mode/compiler/angora_clang.c` | `add_storfuzz_pass()` 함수 추가 및 호출 |
| `runtime_fast/build.rs` | `storfuzz_rt.c` 를 cc::Build에 추가 |
| `common/src/config.rs` | 데이터 맵 크기 상수 추가 |
| `common/src/defs.rs` | `ANGORA_DATA_SHM_ID` 환경변수 상수 추가 |
| `fuzzer/src/lib.rs` | `mod data_cov` 선언 추가 |
| `fuzzer/Cargo.toml` | `storfuzz` feature 및 `[[bin]] angora_storfuzz` 추가 |
| `fuzzer/src/executor/executor.rs` | DataCov 필드, 초기화, 리셋, OR 판정, 통계 갱신, **DATA_SHM_ENV_VAR envs 삽입** 추가 |
| `fuzzer/src/stats/chart.rs` | `data_bits_set` 필드 및 표시 추가 |

---

## 3. 신규 생성 파일 상세

### 3-1. `llvm_mode/pass/StorFuzzPass.cc` (589줄)

StorFuzz-LibAFL의 `storfuzz-coverage-pass.cc`를 LLVM 11 Legacy Pass Manager로 백포트한 LLVM 패스.

**알고리즘 (원본 StorFuzz 동일)**
함수 내 모든 StoreInst를 순회하면서, 다음 조건을 만족하는 store만 계측한다:
- alloca 변수로의 store 제외
- loop counter로 판단되는 store 제외 (LI=nullptr이므로 이 필터는 비활성)
- mem→mem 단순 복사 (load→store) 제외
- 정수형 타입 store만 대상

계측 IR은 다음 순서로 삽입된다:
```
ReducedValue = XOR( Upper8(trunc(stored_val, i16)), Lower8(trunc(stored_val, i16)) )
MapPtr       = load(__angora_data_area_ptr)
Index        = CurLoc XOR zext(ReducedValue, i32)     // CurLoc: 컴파일 시 랜덤 site ID
atomic_or(MapPtr[Index], (1 << bitmask_selector))      // bitmask_selector: 컴파일 시 랜덤 0-7
```

BB 당 store 수가 `MAX_STORES_PER_BB`(기본 9)를 초과하면 해당 BB 전체 건너뜀.
계측은 2-pass 루프로 수행(pass0: 카운트, pass1: IR 삽입).

**LLVM 11 호환 수정 사항 (upstream 대비)**

| upstream (LLVM 15+) | LLVM 11 수정 |
|---------------------|-------------|
| `F.getName().starts_with(s)` | `F.getName().startswith(s)` |
| `isa<LoadInst, VAArgInst>(x)` | `isa<LoadInst>(x) \|\| isa<VAArgInst>(x)` |
| `CreateLoad(Ty, Ptr)` | `CreateLoad(Ptr)` (untyped form) |
| `CreateGEP(Ty, Ptr, Idx)` | `CreateGEP(Ptr, Idx)` (untyped form) |
| `CreateAtomicRMW(..., MaybeAlign(1))` | `CreateAtomicRMW(...)` (no MaybeAlign, added in LLVM 13) |
| `MDNode::get(C, None)` | `MDNode::get(C, {})` |
| `BB.isEntryBlock()` | `&BB == &BB.getParent()->getEntryBlock()` |
| `loop->getLatchCmpInst()` | `CmpInst *cmp_instr = nullptr` (LI=nullptr이므로 dead code) |
| `GlobalValue::ExternalWeakLinkage` | `GlobalValue::ExternalLinkage` (아래 참고) |
| `USE_NEW_PM` 분기 | 제거 (Legacy PM only) |
| `maybeWeakenFunction()` | 제거 (LibAFL in-process 전용) |
| `LazyValueInfo / LVI` | 제거 (new-PM path 전용) |
| `PseudoProbeInst` | 제거 (LLVM 11 미지원) |

**`ExternalWeakLinkage` → `ExternalLinkage` 변경 이유 (중요)**
weak 참조는 static archive에서 object file 포함을 강제하지 않는다.
weak linkage를 쓰면 링커가 `storfuzz_rt.o`를 `libruntime_fast.a`에서 꺼내지 않아
`__angora_data_area_ptr`가 null(주소 0)이 되고, 계측 코드가 이를 역참조하여 **segfault** 발생.
`ExternalLinkage`로 바꾸면 링커가 `storfuzz_rt.o`를 강제 포함시킨다.

**등록 방식 (AngoraPass.cc 패턴 그대로 미러링)**
```cpp
static RegisterStandardPasses RegisterStorFuzzPass(
    PassManagerBuilder::EP_OptimizerLast, registerStorFuzzPass);
static RegisterStandardPasses RegisterStorFuzzPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerStorFuzzPass);
```

---

### 3-2. `runtime_fast/src/storfuzz_rt.c` (62줄)

계측된 대상 바이너리에 링크되는 C 런타임. `libruntime_fast.a`에 포함된다.

**역할**
1. 전역 포인터 `__angora_data_area_ptr` 정의 — 패스가 생성한 IR에서 참조
2. static fallback 버퍼 `__angora_storfuzz_default_map[131072]` 제공 — 퍼저 미연결 시에도 충돌 없이 동작
3. `constructor(200)` 속성의 init 함수 — 프로세스 시작 시 `ANGORA_DATA_SHM_ID` 환경변수를 읽어 shmem에 `attach`, 포인터를 공유 메모리 주소로 교체

```c
uint8_t *__angora_data_area_ptr = __angora_storfuzz_default_map;

__attribute__((constructor(200)))
static void __angora_storfuzz_init(void) {
    const char *id_str = getenv("ANGORA_DATA_SHM_ID");
    if (!id_str) return;
    void *p = shmat(atoi(id_str), NULL, 0);
    if (p != (void *)-1) __angora_data_area_ptr = (uint8_t *)p;
}
```

**per-exec 리셋은 C 측에서 하지 않는다.**
Rust 퍼저(부모 프로세스)가 `DataCov::clear_run_map()`으로 fork 직전에 shmem을 zeroing한다.
이는 브랜치 맵의 `Branches::clear_trace()`와 동일한 패턴.

---

### 3-3. `fuzzer/src/data_cov.rs` (68줄)

`fuzzer/src/branches.rs`의 구조를 그대로 미러링한 Rust 구조체.

```rust
pub struct DataCov {
    virgin: Box<DataBuf>,   // 지금까지 본 모든 비트 누적 (virgin map)
    shm: SHM<DataBuf>,      // 자식 프로세스가 쓰는 공유 메모리
}
```

| 메서드 | 역할 |
|--------|------|
| `new()` | shmem 할당, `ANGORA_DATA_SHM_ID` env var 설정 |
| `clear_run_map()` | 매 실행 전 shmem zeroing (fork 직전 호출) |
| `has_new() -> bool` | 실행 후 virgin map에 없는 비트가 생겼으면 true, virgin map 갱신 |
| `bits_set() -> usize` | virgin map의 총 set 비트 수 (통계용) |

---

### 3-4. `tests/storfuzz_sanity.c` (9줄)

StorFuzz 패스 및 런타임 검증용 최소 libFuzzer 스타일 타깃.

```c
static volatile uint8_t state = 0;
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    if (n < 4) return 0;
    state = d[0]; state ^= d[1]; state += d[2];
    if (state == 0xAB) abort();
    return 0;
}
```

global volatile 변수에 대한 integer store가 3개 존재 (최적화 후 2개 계측됨).

---

## 4. 수정된 기존 파일 상세

### 4-1. `llvm_mode/pass/CMakeLists.txt`

기존 `AngoraPass`, `DFSanPass` 타깃 사이에 `StorFuzzPass` 타깃 추가 (55-57번째 줄):

```cmake
add_library(StorFuzzPass MODULE StorFuzzPass.cc)
target_link_libraries(StorFuzzPass LLVMPassConfig)
install (TARGETS StorFuzzPass DESTINATION ${ANGORA_PASS_DIR})
```

빌드 결과: `bin/pass/libStorFuzzPass.so`

---

### 4-2. `llvm_mode/compiler/angora_clang.c`

두 곳 수정:

**① `add_storfuzz_pass()` 함수 추가 (100-111번째 줄)**
```c
static void add_storfuzz_pass() {
  u8 *use_storfuzz = getenv("ANGORA_USE_STORFUZZ");
  if (clang_type == CLANG_FAST_TYPE && use_storfuzz) {
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] =
        alloc_printf("%s/pass/libStorFuzzPass.so", obj_path);
  }
}
```

핵심 게이트 조건: `USE_FAST=1` AND `ANGORA_USE_STORFUZZ=1`
→ `USE_TRACK=1` (DFSan taint path)에서는 패스를 로드하지 않음.

**② `edit_params()` 내 호출 추가 (276번째 줄)**
```c
if (!maybe_assembler) {
    add_angora_pass();
    add_dfsan_pass();
    add_storfuzz_pass();   // ← 추가
}
```

---

### 4-3. `runtime_fast/build.rs`

`storfuzz_rt.c`를 `context.c`와 함께 `libcontext.a`에 컴파일:

```rust
cc::Build::new()
    .file("src/context.c")
    .file("src/storfuzz_rt.c")   // ← 추가
    .compile("libcontext.a");
```

`libcontext.a`는 최종적으로 `libruntime_fast.a`에 포함되어 `angora-clang`이 링크하는 라이브러리가 된다.

---

### 4-4. `common/src/config.rs`

기존 브랜치 맵 상수(`MAP_SIZE_POW2`, `BRANCHES_SIZE`) 바로 아래에 추가 (18-20번째 줄):

```rust
// data_cov.rs
pub const DATA_MAP_SIZE_POW2: usize = 17;
pub const DATA_COV_SIZE: usize = 1 << DATA_MAP_SIZE_POW2;  // = 131072 bytes
```

StorFuzz 원본의 `STORFUZZ_MAP_SIZE = 1 << 17 = 131072`과 동일한 크기.

---

### 4-5. `common/src/defs.rs`

기존 `BRANCHES_SHM_ENV_VAR` 바로 아래에 추가 (10번째 줄):

```rust
pub static BRANCHES_SHM_ENV_VAR: &str = "ANGORA_BRANCHES_SHM_ID";
pub static DATA_SHM_ENV_VAR: &str     = "ANGORA_DATA_SHM_ID";   // ← 추가
```

---

### 4-6. `fuzzer/src/lib.rs`

`mod data_cov` 선언 추가 (10번째 줄):

```rust
mod data_cov;
```

이 모듈은 `#[cfg(feature = "storfuzz")]` 없이 선언되어 있다. 파일 자체는 항상 컴파일되나,
struct의 메서드는 executor.rs에서 `#[cfg(feature = "storfuzz")]` 게이트 하에서만 호출된다.
(feature 비활성 시 "never used" 경고가 나오는 것이 정상.)

---

### 4-7. `fuzzer/Cargo.toml`

두 가지 변경:

**① `storfuzz` feature 추가**
```toml
[features]
unstable = []
storfuzz = []
```

**② 두 번째 `[[bin]]` 엔트리 추가**
```toml
[[bin]]
name = "fuzzer"
path = "src/bin/fuzzer.rs"

[[bin]]
name = "angora_storfuzz"
path = "src/bin/fuzzer.rs"
required-features = ["storfuzz"]
```

`[[bin]]`을 명시적으로 선언하면 Cargo가 자동 탐지를 멈추므로,
기존 `fuzzer` 바이너리도 명시적으로 선언해야 한다. (누락 시 `bin/fuzzer` 가 사라지는 버그 발생)

---

### 4-8. `fuzzer/src/executor/executor.rs`

총 6곳 수정, 모두 `#[cfg(feature = "storfuzz")]`로 게이트.

**① import 추가 (8-9번째 줄)**
```rust
#[cfg(feature = "storfuzz")]
use crate::data_cov;
```

**② `Executor` 구조체 필드 추가 (27-28번째 줄)**
```rust
#[cfg(feature = "storfuzz")]
pub data_cov: data_cov::DataCov,
```

**③ `Executor::new()` 초기화 (52-53번째 줄, 94-95번째 줄)**
```rust
#[cfg(feature = "storfuzz")]
let data_cov = data_cov::DataCov::new();
// ...
#[cfg(feature = "storfuzz")]
data_cov,
```

**④ `run_inner()` 내 per-exec 리셋 (336-337번째 줄)**
```rust
self.branches.clear_trace();
#[cfg(feature = "storfuzz")]
self.data_cov.clear_run_map();
```

**⑤ `try_unlimited_memory()` 내 per-exec 리셋 (211-212번째 줄)**
unlimited memory로 재실행할 때도 동일하게 리셋.

**⑥ `do_if_has_new()` 내 OR 판정 (240-245번째 줄)**
데이터 커버리지와 브랜치 커버리지의 유일한 교차점:
```rust
let (has_new_path, has_new_edge, edge_num) = self.branches.has_new(status);

#[cfg(feature = "storfuzz")]
let data_new = self.data_cov.has_new();
#[cfg(not(feature = "storfuzz"))]
let data_new = false;

if has_new_path || data_new || self.is_dry_run {
    // 입력을 corpus에 저장
```

**⑦ `update_log()` 내 통계 갱신 (471-472번째 줄)**
```rust
#[cfg(feature = "storfuzz")]
gs.set_data_bits(self.data_cov.bits_set());
```

**⑧ `Executor::new()` — DATA_SHM_ENV_VAR를 envs HashMap에 삽입 (Bug #6 수정)**

자식 프로세스는 `env_clear().envs(&self.envs)` 또는 `Forksrv::new()` 경유로 생성되므로,
shmem ID는 반드시 `envs` HashMap에 명시적으로 삽입해야 한다.
`BRANCHES_SHM_ENV_VAR` 및 `COND_STMT_ENV_VAR`와 동일한 패턴.

```rust
// LD_LIBRARY_PATH 삽입 직후, forksrv 생성 직전:
#[cfg(feature = "storfuzz")]
envs.insert(
    defs::DATA_SHM_ENV_VAR.to_string(),
    data_cov.get_id().to_string(),
);
```

---

### 4-9. `fuzzer/src/stats/chart.rs`

세 곳 수정:

**① `ChartStats` 구조체 필드 추가 (12-13번째 줄)**
```rust
#[cfg(feature = "storfuzz")]
data_bits_set: Counter,
```

**② `set_data_bits()` 메서드 추가 (127-130번째 줄)**
```rust
#[cfg(feature = "storfuzz")]
pub fn set_data_bits(&mut self, n: usize) {
    self.data_bits_set = n.into();
}
```

**③ `Display` 구현에 DATACOV 라인 조건부 출력 (148-151번째 줄)**
```rust
#[cfg(feature = "storfuzz")]
let data_line = format!("  DATACOV  | DATA_BITS: {}\n", self.data_bits_set);
#[cfg(not(feature = "storfuzz"))]
let data_line = String::new();
```

---

## 5. 아키텍처 / 설계 결정사항

### 데이터 흐름 전체 경로

```
[대상 바이너리 (자식 프로세스)]
  StoreInst 실행
  → atomic_or( __angora_data_area_ptr[CurLoc XOR ReducedValue], bitmask )
  → shmem 세그먼트(ANGORA_DATA_SHM_ID)에 기록

[Rust 퍼저 (부모 프로세스)]
  DataCov::clear_run_map()   ← fork 직전
  → fork → 자식 실행
  DataCov::has_new()         ← fork 복귀 후
  → virgin map과 비교, 새 비트 있으면 corpus 저장 (branch OR data)
  DataCov::bits_set()        ← update_log() 시 통계 갱신
```

### 두 맵의 독립성 보장

| 항목 | 브랜치 맵 | 데이터 맵 |
|------|-----------|-----------|
| shmem 환경변수 | `ANGORA_BRANCHES_SHM_ID` | `ANGORA_DATA_SHM_ID` |
| 크기 | `1 << 20` = 1MB | `1 << 17` = 128KB |
| Rust 구조체 | `branches::Branches` | `data_cov::DataCov` |
| 전역 포인터 | `__angora_area_ptr` | `__angora_data_area_ptr` |
| LLVM 패스 | `AngoraPass` | `StorFuzzPass` |
| 리셋 호출 | `branches.clear_trace()` | `data_cov.clear_run_map()` |

두 맵은 **절대 메모리를 공유하거나 OR 연산하지 않는다.**
유일한 교차점은 executor.rs의 `has_new_path || data_new` OR 판정뿐이다.

### per-exec 리셋 위치

Angora의 fork-server 모델에서 부모가 fork 직전에 `branches.clear_trace()`를 호출해
shmem을 초기화한다. 이와 동일한 패턴으로 `data_cov.clear_run_map()`도 같은 위치(`run_inner()` 첫머리)에 배치했다.
C 런타임(storfuzz_rt.c)에서는 리셋을 수행하지 않는다.

---

## 6. 검증 중 발견된 버그 및 수정

### Bug 1: `BasicBlock::isEntryBlock()` LLVM 11 미존재
**위치**: `StorFuzzPass.cc:91`
**증상**: 컴파일 오류 `'class llvm::BasicBlock' has no member named 'isEntryBlock'`
**수정**: `insertionBB->isEntryBlock()` → `insertionBB == &insertionBB->getParent()->getEntryBlock()`

### Bug 2: `Loop::getLatchCmpInst()` LLVM 11 미존재
**위치**: `StorFuzzPass.cc:213`
**증상**: 컴파일 오류 `'class llvm::Loop' has no member named 'getLatchCmpInst'`
**수정**: `CmpInst *cmp_instr = nullptr` (LI=nullptr이므로 이 코드는 실행 불가, dead code 처리)

### Bug 3: `ExternalWeakLinkage` — 아카이브 멤버 미포함 (Critical)
**위치**: `StorFuzzPass.cc:270`, `runtime_fast/src/storfuzz_rt.c`
**증상**: 계측된 바이너리가 실행 시 segfault 발생
**원인**: weak 외부 참조는 static archive에서 object file 포함을 강제하지 않음.
따라서 `libruntime_fast.a` 내 `storfuzz_rt.o`가 링크에서 누락되고,
`__angora_data_area_ptr`가 주소 0(null)으로 남아 역참조 시 segfault.
**진단**: `nm /tmp/sanity_fast_bin | grep angora_data` → `w __angora_data_area_ptr` (undefined weak, no address)
**수정**: `ExternalWeakLinkage` → `ExternalLinkage`
**수정 후**: `D __angora_data_area_ptr @ 0x157070` (defined data symbol)

### Bug 4: `python` 바이너리 미존재 (dfsan symbols 빌드 단계)
**위치**: `llvm_mode/build` make 과정
**증상**: `make install` 실패 (`/usr/bin/env: 'python': No such file or directory`)
**수정**: `ln -s /usr/bin/python3 ~/clang+llvm/bin/python`

### Bug 5: `fuzzer` 바이너리 사라짐
**위치**: `fuzzer/Cargo.toml`
**증상**: `[[bin]]` 엔트리를 추가하면 Cargo가 자동 탐지를 중단, `fuzzer` 바이너리 미생성
**수정**: `angora_storfuzz` 외에 `fuzzer`도 명시적 `[[bin]]` 엔트리로 선언

---

## 7. 검증 결과

### 검증 항목 1: StorFuzzPass 패스 작동 확인

```bash
ANGORA_USE_STORFUZZ=1 USE_FAST=1 STORFUZZ_VERBOSE=1 \
  ./bin/angora-clang -O2 -c tests/storfuzz_sanity.c -o /tmp/sanity.o
```

출력:
```
angora-llvm-pass
[+] Fast Mode.
StorFuzzPass: Instrumented 2 stores in 'tests/storfuzz_sanity.c'
```

storfuzz_sanity.c의 3개 store 중 2개 계측 (-O2에서 컴파일러가 1개 최적화 제거).

### 검증 항목 2: 런타임 shmem 쓰기 확인

C 하네스를 통해 shmem 할당 후 실행:
```
nonzero_bytes=2  bits_set=2
```

### 검증 항목 3: 기본 `fuzzer` 바이너리 — DATA_BITS 부재 확인

```bash
strings bin/fuzzer | grep -i "data_bit\|datacov"
# → 출력 없음 (correct)
```

### 검증 항목 4: `angora_storfuzz` 바이너리 — DATA_BITS > 0 실시간 확인

약 5초 후 stats 화면:
```
   ANGORA    (\_/)
   FUZZER    (x'.')
 -- OVERVIEW --
    TIMING |     RUN: [00:00:00],   TRACK: [00:00:00]
  COVERAGE |    EDGE:    2.00,   DENSITY:    0.00%
  DATACOV  | DATA_BITS:       2
    EXECS  |   TOTAL:       1,     ROUND:       1,     MAX_R:       0
    SPEED  |  PERIOD:    0.20r/s    TIME:  304.00us,
    FOUND  |    PATH:       1,     HANGS:       0,   CRASHES:       0
```

### 검증 항목 5: 기본 `fuzzer` 실행 — DATACOV 라인 없음 확인

```
 -- OVERVIEW --
    TIMING |     RUN: [00:00:05],   TRACK: [00:00:00]
  COVERAGE |    EDGE:    2.00,   DENSITY:    0.00%
    EXECS  |   TOTAL:       1,     ROUND:       1,     MAX_R:       0
    FOUND  |    PATH:       1,     HANGS:       0,   CRASHES:       0
```

DATACOV 라인 없음 — `fuzzer` 바이너리 동작 변화 없음 확인.

---

## 8. 빌드 방법

### 환경 설정

```bash
# LLVM 11.1.0 설치 위치
export PATH=$HOME/clang+llvm/bin:$PATH
export LD_LIBRARY_PATH=$HOME/clang+llvm/lib:$LD_LIBRARY_PATH

# cmake (pip3 install cmake)
export PATH=$(python3 -c "import cmake,os; print(os.path.dirname(cmake.CMAKE_BIN_DIR))"):$PATH

# python 심볼릭 링크 (dfsan 빌드 단계 필요)
# ln -s /usr/bin/python3 ~/clang+llvm/bin/python  ← 최초 1회만
```

### LLVM 패스 빌드

```bash
cd llvm_mode/build
make -j$(nproc) && make install
# 결과: bin/pass/libStorFuzzPass.so
```

### Rust 바이너리 빌드

```bash
# 기본 angora 바이너리
cargo build --release
# 결과: target/release/fuzzer  →  bin/fuzzer

# angora_storfuzz 바이너리
cargo build --release --features storfuzz
# 결과: target/release/angora_storfuzz  →  bin/angora_storfuzz
```

### 대상 프로그램 컴파일

```bash
# fast 계측 (storfuzz 포함)
ANGORA_USE_STORFUZZ=1 USE_FAST=1 ./bin/angora-clang -O2 target.c -o target_fast

# track 계측 (DFSan, storfuzz 패스 없음)
USE_TRACK=1 ./bin/angora-clang -O2 target.c -o target_track
```

### 퍼저 실행

```bash
./bin/angora_storfuzz -i input_dir -o output_dir -t target_track -- target_fast @@
```

---

## 9. 환경 변수 참조

| 변수 | 설정 주체 | 용도 |
|------|-----------|------|
| `USE_FAST=1` | 사용자 | angora-clang fast 빌드 모드 |
| `USE_TRACK=1` | 사용자 | angora-clang track(DFSan) 빌드 모드 |
| `ANGORA_USE_STORFUZZ=1` | 사용자 | StorFuzzPass 로드 활성화 (USE_FAST 필수) |
| `ANGORA_DATA_SHM_ID` | Rust 퍼저 | 데이터 커버리지 shmem ID 전달 |
| `ANGORA_BRANCHES_SHM_ID` | Rust 퍼저 | 브랜치 커버리지 shmem ID 전달 (기존) |
| `STORFUZZ_VERBOSE=1` | 사용자 | 패스가 계측한 store 수 stderr 출력 |
| `MAX_STORES_PER_BB` | 사용자 | BB당 최대 계측 store 수 (기본 9) |
| `VALUE_REDUCTION_WIDTH` | 사용자 | 값 축약 비트 폭: 4/8/12/16 (기본 8) |
| `STORFUZZ_MAP_SIZE` | 빌드 시 | 데이터 맵 크기 (기본 1<<17=131072) |

---

## 10. 범위 외 (Out of scope)

다음 항목은 이번 구현에 **포함되지 않았다**:

- DFSan taint track 빌드에 StorFuzz 패스 적용 (Option 2 — 별도 마일스톤)
- 데이터 커버리지 novelty를 cond_stmt 또는 GD 스케줄러에 반영 (Option 2/3)
- 브랜치 맵과 데이터 맵의 어떠한 융합도 없음
- 기존 mutation operator, scheduler, seed-prioritization 변경 없음
- DFSanPass.cc, dfsan_abilist.txt 변경 없음
- LLVM, Rust toolchain, crate 의존성 버전 변경 없음
