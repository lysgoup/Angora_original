# Reusing mutation — 이식을 위한 레퍼런스

이 문서는 `/home/yunseo/Reusing_mut` (별도 git 저장소, `lysgoup/Reusing_mut.git`, 브랜치 `reusing_ver2`
HEAD `3feeba3`)에 구현되어 있는 **reusing mutation** 개념을 이 저장소(`Angora_original`)에
이식하기 위해 코드를 통째로 읽고 정리한 레퍼런스다. Reusing_mut은 Angora_original과 같은
Angora 코드베이스의 별도 fork이며, reusing 외에도 StorFuzz(`data_cov`), dry-run 카운터,
`analysis_mode` CSV 로깅 등 서로 무관한 기능들이 같은 파일에 섞여 있으므로, 아래에서는
**reusing 자체에 필요한 부분**과 **곁다리로 딸려온 다른 기능**을 구분해서 표시한다.

## 1. 핵심 아이디어

Angora의 GD(gradient-descent) 탐색은 새로 발견된 CondStmt마다 taint offset 값을 항상
처음부터 탐색한다. 하지만 taint 세그먼트 길이 패턴(예: 4바이트 정수 하나, 혹은 1+2바이트
조합)이 같은 서로 다른 CondStmt는 종종 비슷한 critical value(매직 넘버/문자열, 길이 값 등)로
풀린다. **reusing은 과거에 어떤 CondStmt를 풀었거나(조건이 바뀌었거나) 새 엣지를 낸 입력에서
critical byte 값을 캐시해뒀다가, 세그먼트 길이 패턴이 일치하는 다른 CondStmt에 그 값을 그대로
대입해 먼저 시도**함으로써 GD 탐색의 지름길을 제공하는 최적화다.

핵심 전제: `cond.base.belong`이 "이 CondStmt를 실제로 만들어낸 입력의 depot id"를 정확히
가리켜야 한다 — reusing이 critical value를 뽑아낼 때 바로 이 필드로 입력 버퍼를 가져오기
때문이다(`depot.get_input_buf(cond.base.belong)`). Angora_original에서 이미 고친
"AFL cond의 `belong`이 항상 0으로 남는" 버그(`get_afl_cond`)가 바로 이 전제조건이었고,
Reusing_mut에도 동일한 수정(`afl_cond.base.belong = id as u32;`, `cond_stmt.rs:125`)이
들어가 있다. **reusing을 이식하기 전에 이 fix가 먼저 들어가 있어야 AFL cond 계열의 reusing
데이터가 올바른 입력에서 뽑힌다.**

## 2. 자료구조: `LABEL_PATTERN_MAP`

새 파일 `fuzzer/src/depot/label_pattern_tracker.rs`가 필요하다. 프로세스 전역(스레드 간 공유)
`Mutex<HashMap<LabelPattern, Vec<CondRecord>>>`.

```rust
pub type LabelPattern = Vec<u32>;   // 각 (병합된) 세그먼트의 byte 길이 목록

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CondRecord {
    pub cmpid: u32,
    // order/context/op/lb1/lb2/condition/belong/arg1/arg2는 한때 더 정교한 매칭을
    // 하려고 있었으나 현재는 전부 주석 처리된 죽은 필드 — 이식할 때는 아예 빼도 된다.
    pub offsets: Vec<TagSeg>,
    pub critical_values: Vec<Vec<u8>>,
}

lazy_static! {
    pub static ref LABEL_PATTERN_MAP: Mutex<HashMap<LabelPattern, Vec<CondRecord>>> =
      Mutex::new(HashMap::new());
}

pub fn extract_pattern(offsets: &Vec<TagSeg>) -> LabelPattern {
  offsets.iter().map(|seg| seg.end - seg.begin).collect()
}
```

- `Depot`에 속한 필드가 아니라 `lazy_static` 전역 상태 — 모든 fuzz_loop 스레드가 이 맵
  하나를 공유한다.
- `extract_pattern`은 **병합된(연속 세그먼트 merge) 이후의** offsets에 대해 계산해야 한다.
  연속 세그먼트 병합용 헬퍼(`merge_continuous_segments`, `fuzzer/src/mut_input/offsets.rs`)가
  Angora_original에는 아직 없으므로 함께 추가해야 한다:

  ```rust
  // 인접 세그먼트(current.end == next.begin)를 하나로 합침
  // 예: [0..2, 2..4, 7..8] -> [0..4, 7..8]. offsets가 begin 기준 정렬돼 있다고 가정.
  pub fn merge_continuous_segments(offsets: &Vec<TagSeg>) -> Vec<TagSeg> { ... }
  ```
  (`merge_offsets`는 offsets/offsets_opt 병합용으로 Angora_original에 이미 있음.)

### 레코드 생성 (`create_record_for_offsets`)

```rust
fn create_record_for_offsets(offsets: &Vec<TagSeg>, cond: &CondStmt, depot: &Depot, operand_num: u8) {
    if offsets.is_empty() { return; }

    let merged_offsets = merge_continuous_segments(offsets);
    let pattern = extract_pattern(&merged_offsets);
    let input_buf = depot.get_input_buf(cond.base.belong as usize);
    let critical_values = extract_value_from_merged(&merged_offsets, &input_buf);

    // 1) 전체 패턴 레코드
    create_single_record(&pattern, offsets, &critical_values, cond, operand_num);

    // 2) 세그먼트가 2개 이상이면, 세그먼트별 "단일 패턴" 레코드도 별도 저장
    //    -> 이후 "combining reusing"(서로 다른 cond의 부분 값을 조합)의 재료가 됨
    if merged_offsets.len() > 1 {
        for i in 0..merged_offsets.len() {
            create_single_record(&vec![len(i)], &vec![merged_offsets[i]], &vec![critical_values[i].clone()], cond, operand_num);
        }
    }
}
```

`create_single_record`는 같은 패턴에 이미 동일한 `critical_values`를 가진 레코드가 있으면
중복 추가하지 않는다(선형 스캔 dedup).

`extract_value_from_merged`는 입력 버퍼에서 각 세그먼트의 바이트를 그대로 슬라이스하되,
버퍼가 세그먼트 범위보다 짧으면 0으로 패딩한다(입력이 이후 축소된 경우 대비).

### 언제 채워지는가 (`add_cond_to_pattern_map`)

```rust
pub fn add_cond_to_pattern_map(cond: &CondStmt, depot: &Depot) {
    if cond.base.lb1 > 0 && cond.base.lb2 == 0 { add_single_label_record(cond, depot); }
    else if cond.base.lb1 == 0 && cond.base.lb2 > 0 { add_single_label_record(cond, depot); }
    else if cond.base.lb1 > 0 && cond.base.lb2 > 0 { add_dual_label_records(cond, depot); }
    // lb1==0 && lb2==0 (테인트 없음)인 경우는 아무 분기도 안 타서 조용히 no-op
}
```
- `add_single_label_record`: `cond.offsets` 하나만 기록.
- `add_dual_label_records`: `offsets_opt`도 있으면(양쪽 오퍼랜드 모두 테인트) `offsets`와
  `offsets_opt`를 각각 독립적으로 기록.

호출 지점은 `Depot::add_entries` / `add_entries_with_filter` 내부, 새 cond를 큐에 처음
push하거나 기존 cond가 "탐색 완료(조건이 뒤바뀜)"로 판정돼 `mark_as_done()`될 때다
(즉 `executor.rs`의 `do_if_has_new` → `self.track()`으로 새 CondStmt들을 뽑아내
`depot.add_entries*`를 호출하는 시점과 동일). `enable_reusing` 플래그로 게이팅된다.

`add_entries_with_filter` + `add_cond_to_pattern_map_with_filter`는 이번 실행에서 실제로
뮤테이션된 offset(`mutated_offsets: &HashSet<u32>`, 아래 §5)과 겹치는 cond만 풀에 등록해
잡음을 줄이는 선택적 최적화다. `mutated_offsets`가 비어 있으면(초기 시드 등) 필터 없이 그냥
등록한다.

## 3. `CondStmt` / `CondState`에 추가되는 필드

`fuzzer/src/cond_stmt/cond_stmt.rs`:
```rust
pub struct CondStmt {
    ...
    // AFL cond(get_afl_cond)에 딸린, 이 입력에서 새로 발견된 모든 cond의 offsets/offsets_opt
    // 그룹 목록. 각 cond의 offsets 그룹과 offsets_opt 그룹을 절대 섞지 않고 별도 항목으로 저장.
    pub afl_offset_groups: Vec<Vec<TagSeg>>,
    ...
    pub reusing_record_index: usize,      // "이 offsets 패턴에서 몇 번째 레코드까지 시도했는가" 커서
    pub reusing_record_index_opt: usize,  // offsets_opt 쪽 전용 커서 (분리해야 Phase A/B가 서로 안 꼬임)
}
```
`clear()` / `mark_as_done()`에서 `afl_offset_groups`도 함께 비워야 한다.

`get_afl_cond`(이미 belong 수정 완료)에서, `enable_afl && enable_reusing`일 때만
`executor.rs`가 이번 실행에서 나온 모든 CondStmt의 offsets/offsets_opt를 모아
`afl_cond.afl_offset_groups`에 채워 넣는다(§6 AFL 통합 참고).

`fuzzer/src/cond_stmt/cond_state.rs`: 새 상태 `OffsetAllEnd`가 추가됨(Offset → OffsetOpt →
OffsetAll → **Deterministic** → **OffsetAllEnd**). 현재 코드에서 이 상태 자체에 대한 별도
분기 로직은 거의 없고(과거 커밋에선 이 상태에서만 reusing을 허용하도록 게이팅했었으나
현재는 완화됨), `next_state()`의 `Deterministic => to_offsets_all_end()` 전환만 존재.
포팅 시 이 상태를 그대로 가져갈지, 아니면 생략하고 기존 상태 전이만으로 충분한지는
구현 시 판단 필요.

상태 전이 시 reusing 커서도 함께 관리해야 한다:
```rust
fn to_offsets_opt(&mut self) {
    self.state = CondState::OffsetOpt;
    std::mem::swap(&mut self.offsets, &mut self.offsets_opt);
    std::mem::swap(&mut self.reusing_record_index, &mut self.reusing_record_index_opt); // 오퍼랜드가 바뀌므로 커서도 같이 스왑
}
fn to_offsets_all(&mut self) {
    self.state = CondState::OffsetAll;
    self.offsets = merge_offsets(&self.offsets, &self.offsets_opt);
    self.reusing_record_index = 0; // 병합된 새 패턴이므로 커서 리셋
}
```

## 4. 알고리즘: `fuzzer/src/search/reusing.rs`

```rust
pub enum ReusingOutcome { Solved, Improved, NoProgress }

pub struct ReusingFuzz<'a, 'b> { pub handler: &'b mut SearchHandler<'a> }
```

`ReusingFuzz::run(iterations: usize) -> ReusingOutcome`의 흐름:

1. `cond.is_done()`이거나 `cond.offsets`가 비어 있으면 즉시 `NoProgress`.
2. `buf_backup = handler.buf.clone()` — 실패 시 원복용.
3. **Phase A** (`run_reusing_phase`): `handler.cond.offsets`(state가 Offset/OffsetOpt처럼
   이르면 한쪽 오퍼랜드, OffsetAll 이후면 이미 병합된 전체)를 대상으로 시도. 진행 상황은
   `cond.reusing_record_index`에 누적.
4. **Phase B**: `state`가 아직 `Offset`/`OffsetOpt`(즉 두 오퍼랜드가 아직 분리된 이른 단계)일
   때만, 반대쪽 `offsets_opt`에 대해 별도 커서(`reusing_record_index_opt`)로 동일 시도를
   반복. OffsetAll 이후에는 `cond.offsets`가 이미 병합돼 있으므로 Phase A 한 번으로 충분.
5. 통계 델타를 전역 `REUSING_STATS`와 `local_stats.reusing_num_*`에 누적(§7).
6. **개선이 있었을 때만(`best_f < u64::MAX`) `handler.buf`를 `best_buf`로 교체, 없으면
   `buf_backup`으로 원복.** 이 복원 로직은 나중에 추가된 것으로, 초기 구현(`ffdeb81`)에는
   없었고 실패한 마지막 시도값이 `handler.buf`에 그대로 남아 이어지는 GD/Det 단계가 오염된
   베이스 버퍼로 시작하는 버그가 있었다(`6f2efc8`에서 수정). **이식할 때 반드시 포함해야 하는
   부분.**
7. `cond.is_done()`이면 `Solved`, 아니면 개선 여부에 따라 `Improved`/`NoProgress`.

### `run_reusing_phase` (Phase A/B 공통 실행부)
- 현재 `cond.offsets`를 `merge_continuous_segments` → `extract_pattern`.
- `LABEL_PATTERN_MAP`에서 동일 패턴 레코드를 `record_index`부터 `iterations`개
  (`get_next_records`)만큼 순서대로 꺼냄(전부 소진했으면 skip 로그만 남기고 조기 종료).
- 레코드마다: `insert_critical_value_with_merged`로 critical_values를 offset 위치에
  써넣고 — **원본 버퍼와 완전히 같은 값이면(`matches_original`) 실행 자체를 생략**해서 이미
  알고 있는 실행을 낭비하지 않음 — `execute_cond_direct()`로 직접 실행.
- `f`(목적함수 거리) 갱신 시마다 `best_f`/`best_buf` 갱신, 그리고 아직 안 풀렸으면
  `run_det_for_coverage`(해당 세그먼트에 대한 비트플립, `"Reusing+Det"` 태그)까지 곁들임.
- 이 단계에서 `iterations`를 다 못 채우고 **패턴이 2개 이상의 세그먼트**로 이뤄져 있으면
  `try_combined_segments` 호출.

### `try_combined_segments` (조합 reusing)
패턴의 각 세그먼트 크기별로 "단일 세그먼트 패턴" 풀(§2에서 별도 저장해둔 것)에서 값을
하나씩 랜덤하게 뽑아 조합 — 즉 "세그먼트 1은 CondX에서 관찰된 값, 세그먼트 2는 CondY에서
관찰된 값"을 섞어 새로운 조합을 시도한다. 어느 한 세그먼트라도 풀이 비어 있으면 조합
자체를 포기.

### 버퍼 원복 헬퍼
- `matches_original(merged_offsets, values, original_buf)`: 후보 값이 원본 버퍼와
  완전히 같은지 확인 — 같으면 실행 낭비 방지용으로 스킵.
- `insert_critical_value_with_merged`: 패턴 길이 불일치, 원본과 동일한 값이면 `false`
  반환(스킵), 아니면 버퍼 크기를 필요시 늘리고(`resize`) 값을 써넣고 `true`.

## 5. `mutated_offsets` 추적 (filter용 부가 배선)

`SearchHandler`에 `mutated_offsets: HashSet<u32>` 필드와
`record_mutated_offset/record_mutated_range/clear_mutated_offsets/get_mutated_offsets`가
추가됨. `execute*` 계열 메서드 호출 직전에 매번
`self.executor.set_mutated_offsets(self.mutated_offsets.clone())`로 executor에 복사해두고,
`executor.current_mutated_offsets`는 `do_if_has_new`에서
`depot.add_entries_with_filter(cond_stmts, &self.current_mutated_offsets)`로 흘러가
§2의 필터링에 쓰인다. AFL(`havoc_flip`)과 Det/GD 등 각 탐색 전략이 실제로 건드린 바이트
범위를 스스로 `record_mutated_range`/`record_mutated_offset`으로 기록해줘야 한다(예:
`afl.rs`의 `havoc_flip` 반환값을 루프에서 `record_mutated_offset`으로 등록,
`run_det_for_coverage`도 세그먼트 전체를 `record_mutated_range`).

이 부분은 **reusing의 핵심은 아니고 선택적 정밀화**다 — 없어도 `add_cond_to_pattern_map`
(필터 없는 버전)만으로 reusing 자체는 동작한다. 이식 초기 버전에서는 생략하고 나중에
추가해도 무방.

## 6. AFL 뮤테이션 통합 (`search/afl.rs`)

`ReusingFuzz`를 별도 호출하는 대신, `havoc_flip`의 선택지(choice) 하나로 녹여 넣었다:

- `--enable-reusing`일 때만 기존 선택지 수(base_choice, micro-random-len 여부에 따라
  6 또는 8) 위에 슬롯 하나(`reusing_choice = base_choice`)를 추가.
- 이 선택지가 뽑히면 `cond.afl_offset_groups`(§3, 이 입력에서 나온 모든 cond의 offset
  그룹들)에서 랜덤하게 그룹 하나를 골라 `merge_continuous_segments` → `extract_pattern`,
  `LABEL_PATTERN_MAP`에서 같은 패턴의 레코드를 랜덤하게 하나 뽑아 그 값을 정확히 그
  그룹의 offset 위치에 splat.
- `afl_offset_groups`는 `executor.rs`의 `do_if_has_new`에서 `enable_afl && enable_reusing`일
  때만 채워짐(비용 절감 — reusing이 꺼져 있으면 그룹을 모을 이유가 없음).

## 7. 파이프라인 배선 (`fuzz_loop.rs`) — 새 FuzzType이 아님

`ReusingFuzz`는 `FuzzType`에 새 항목을 추가한 게 아니라, 기존 분기 안에 **전처리 단계**로
끼워 넣는 형태다:

| FuzzType | 배선 |
|---|---|
| `ExploreFuzz` | `state.is_one_byte()`가 아니면 먼저 `ReusingFuzz::run(50)`. `Solved`면 GD/Det/OneByte 전부 스킵. `Improved`면 다음 단계 이름에 `"Reusing+"` 접두어만 붙이고(`"Reusing+GD"` 등) 계속 진행 |
| `ExploitFuzz` | 마찬가지로 먼저 시도하지만, `is_done()`(Solved)이어도 **OneByte/Exploit(크래시 탐색)은 스킵하지 않음** — exploit은 "조건 풀기"가 목적이 아니라 크래시 유발이 목적이므로 |
| `CmpFnFuzz` | reusing으로 풀리면 `FnFuzz`(비교함수 뮤테이션)를 생략 |
| `AFLFuzz` | 별도 호출 없음 — §6처럼 `havoc_flip` 내부에 녹아 있음 |
| `LenFuzz` | 관여 안 함 |

OneByte 상태를 reusing에서 제외하는 이유(코드 주석 그대로): OneByte는 `OneByteFuzz`가
0..256을 전부 시도해 뒤집히는 즉시 멈추는 완전탐색이라, reusing의 추측이 끼어들어봐야
오버헤드만 늘 뿐 절약되는 게 없기 때문.

## 8. CLI 플래그 / 전체 배선 경로

옵트인, 기본 꺼짐:
```
bin/fuzzer.rs      --enable-reusing 플래그 정의
  -> fuzz_main()    enable_reusing: bool 파라미터
    -> command::CommandOpt::new(..., enable_reusing)   // executor가 cmd.enable_reusing으로 참조
    -> depot::Depot::new(seeds_dir, out_dir, enable_reusing)  // add_entries*에서 사용
```
꺼져 있으면 `LABEL_PATTERN_MAP`이 항상 비어 있으므로 완전한 no-op(성능 영향 없음).

종료 시(`fuzz_main.rs` 마지막): `enable_reusing`이면 풀 통계를 출력하고
`depot::save_to_text()`로 `<out_dir>/label_patterns.txt`에 전체 맵을 덤프(패턴별 레코드 수,
cmpid, offsets, critical values 16진수) — 사후 분석/디버깅용. Angora_original 이식 시
필수는 아니고, 있으면 튜닝에 유용한 수준.

## 9. 통계 / 로깅

- `fuzzer/src/stats/reusing.rs`: 전역 `REUSING_STATS: Mutex<ReusingStats>`
  (`num_exec/num_inputs/num_hangs/num_crashes/total_time`). `ReusingFuzz::run` 종료 시
  실행 전후 `local_stats` 스냅샷 차이(delta)를 여기 누적.
- `local.rs`에 `reusing_num_exec/inputs/hangs/crashes` 카운터를 별도로 두어, 같은 delta를
  로컬에도 남김. `chart.rs::sync_reusing_stats`가 **grand total(전체 총합)에는 reusing
  실행도 포함**시키되, **Explore/Exploit 등 FuzzType별 세부 집계에서는 그 몫을 뺀다** —
  reusing이 사실은 ExploreFuzz/ExploitFuzz/CmpFnFuzz 처리 도중에 실행되는데, 그 실행을
  그대로 두면 "Explore가 이만큼 실행했다"는 숫자에 reusing 몫까지 이중으로 잡히기 때문.
  포팅 시 이 이중계산 방지 로직을 빠뜨리면 UI 통계가 왜곡된다.
- (선택, Reusing_mut 전용) `analysis_mode`가 켜져 있으면 `executor.rs`가
  `current_mut_op`(`"Reusing"`/`"Reusing+Det"`/`"GD"`/... 문자열 태그)과
  `current_reusing_detail`(세그먼트 begin/end + 사용된 값의 hex)을 CSV
  (`new_input_id,parent_input_id,mut_op,reusing_detail`)로 남겨 어떤 입력이 reusing으로
  발견됐는지 사후 분석 가능하게 한다. 이건 reusing 고유 기능이라기보다 Reusing_mut의
  범용 분석 로깅 인프라(`analysis_mode`, `current_parent_input`)에 얹혀 있는 것이라,
  Angora_original에 그 인프라가 없다면 최소 구현에서는 생략 가능.

## 10. 알려진 허점 / 미완성 흔적 (이식 시 참고)

- `CondRecord`의 `order/context/op/lb1/lb2/condition/belong/arg1/arg2` 필드는 전부
  주석 처리된 죽은 코드 — 이식할 땐 애초에 넣지 않는 게 깔끔하다.
- `add_cond_to_pattern_map`은 `lb1==0 && lb2==0`(테인트 라벨이 전혀 없는 cond, 예: AFL cond
  자체나 순수 길이 비교)인 경우 아무 분기도 안 타서 **조용히 아무 것도 안 한다** — 의도된
  동작인지 재확인 필요.
- `run_det_for_coverage`는 `min(input.val_len() << 3, MAX_SEARCH_EXEC_NUM)`으로 캡을 걸지만,
  reusing 성공 뒤 곁들이는 이 "Reusing+Det" 비트플립 루프가 세그먼트가 크면 추가 실행
  비용이 꽤 될 수 있다(명시적 경고/TODO는 없음).
- Reusing_mut 저장소에는 `label_pattern_tracker.rs`를 통째로 걷어내고
  `depot/reuse_pool.rs`로 재작성한 훨씬 큰 리팩터 커밋(`8d0f542` "optimizing reusing pool",
  `53427d3` "refine reusing mutation")이 존재하지만, **현재 체크아웃된 `reusing_ver2`
  브랜치(HEAD `3feeba3`)의 조상이 아니다** — 다른 실험 브랜치에만 남아 있고 지금 동작 중인
  코드는 이 문서에서 설명한 `label_pattern_tracker.rs` + `LABEL_PATTERN_MAP` 방식이다.
  이식 대상은 이 문서 기준(HEAD `3feeba3`)이 맞는지, 아니면 그 리팩터 브랜치까지 참고할지
  판단이 필요하면 `git log --oneline --all | grep -i reusing`으로 다른 브랜치를 확인할 것.

## 11. 이식 체크리스트 (제안 순서)

1. `mut_input/offsets.rs`에 `merge_continuous_segments` 추가.
2. `cond_stmt.rs`에 `reusing_record_index`/`reusing_record_index_opt` 필드 추가(+ `new()`/`clear()` 반영), `cond_state.rs`의 `to_offsets_opt`/`to_offsets_all`에 커서 스왑/리셋 추가.
3. `depot/label_pattern_tracker.rs` 신설(§2) — `LabelPattern`/`CondRecord`/`LABEL_PATTERN_MAP`/`extract_pattern`/`add_cond_to_pattern_map`/`get_next_records`.
4. `command.rs`/`bin/fuzzer.rs`/`fuzz_main.rs`/`depot.rs`에 `enable_reusing` 플래그 배선.
5. `depot::add_entries`에서 cond를 처음 push하거나 done 처리할 때 `add_cond_to_pattern_map` 호출.
6. `search/reusing.rs` 신설(§4) — `ReusingFuzz`/`run_reusing_phase`/`try_combined_segments`.
7. `fuzz_loop.rs`에서 `ExploreFuzz`/`ExploitFuzz`/`CmpFnFuzz` 진입 시 `ReusingFuzz` 전처리 호출(§7).
8. (선택) `afl_offset_groups` + AFL `havoc_flip` splat 통합(§6).
9. (선택) `mutated_offsets` 필터링(§5), `stats/reusing.rs` + 이중계산 방지(§9), `analysis_mode` CSV 로깅.

1~7까지만 해도 reusing의 핵심 효과(GD 탐색 지름길)는 그대로 얻을 수 있고, 8~9는 각각
독립적으로 나중에 추가 가능한 정밀화/가시성 개선이다.
