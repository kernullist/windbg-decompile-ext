# Windbg Decompile Extension Roadmap

## 목표

이 문서는 현재 확장의 디컴파일 품질을 끌어올리고, WinDbg 안에서 더 신뢰 가능하고 탐색하기 쉬운 사용자 경험을 제공하기 위한 실행 계획서다.

핵심 방향은 다음 두 가지다.

1. LLM 이전 단계의 분석 품질을 높여 더 정확한 사실(facts)을 만든다.
2. WinDbg 사용자들이 결과를 더 쉽게 이해하고 검증하고 재활용할 수 있게 한다.

## 현재 상태 요약

현재 확장은 다음 요소를 이미 갖추고 있다.

- x64 함수 범위 복구
- Zydis 기반 디스어셈블
- basic block / CFG 수준 정보
- 메모리 접근, call site, switch 후보 수집
- 인자/로컬/merge/조건식의 휴리스틱 복구
- SSA-like IR value facts, def-use hints, copy/constant canonicalization, dead-definition hints
- dominator 기반 control-flow region 후보(natural loop, if/else, switch)
- x64 ABI facts(shadow/home slot, prolog/epilog, no-return, tail-call, thunk/import-wrapper 후보)
- PDB 기반 함수/파라미터/로컬/필드/enum/source 힌트
- LLM 단일 패스 + chunked multi-pass 분석
- loop/switch/no-return evidence를 포함한 verifier 기반 후처리 검증

현재 강점은 "LLM에게 아무것도 맡기지 않고, 가능한 많은 구조화된 사실을 먼저 만든다"는 점이다.
P0 분석 코어의 초기 구현은 들어갔지만, 다음 영역은 아직 본격적인 디컴파일러 수준으로 올라갈 여지가 크다.

- IR/SSA의 block 간 value propagation과 alias 정밀도
- post-dominator / region tree 기반의 고급 control-flow structuring
- 정교한 타입 전파와 시그니처 복구 부족
- 인터프로시저 요약 부족
- WinDbg data model / DML / TTD와의 UX 통합 부족

## 제품 비전

이 프로젝트는 범용 오프라인 디컴파일러를 새로 만드는 것보다, 아래 조합을 강점으로 삼는 것이 가장 현실적이다.

- live debugging context
- loaded PDB and symbol state
- WinDbg extension ecosystem
- TTD 기반 동적 사실
- 구조화된 analyzer facts
- LLM refinement

즉, "WinDbg 안에서 가장 실용적인 디컴파일 보조 확장"을 목표로 한다.

## 우선순위

### P0. 분석 품질 상향

가장 먼저 투자해야 할 영역이다. LLM 품질보다 상한이 더 크다.

상태:

- 2026-04-25 기준 P0 초기 구현 완료
- 새 analyzer facts: `ir_values`, `control_flow`, `abi`
- 새 no-return override: `DECOMP_NORETURN_OVERRIDES`
- 새 verifier check: loop/switch/no-return claim과 analyzer evidence 대조
- README 반영 완료

남은 방향:

- 현재 구현은 "구조화된 evidence를 안정적으로 만들고 LLM/verifier에 전달하는 1차 기반"이다.
- 다음 단계는 더 강한 alias/type propagation, post-dominator 기반 region tree, unwind metadata 심화 해석, regression snapshot 테스트다.

#### 1) 내부 IR/SSA 계층 도입

목표:

- instruction 나열 중심 분석에서 벗어나 value-level data flow를 추적할 수 있는 기반 확보
- register rename, stack slot merge, constant propagation, dead assignment 제거 기반 마련

구현됨:

- 함수 단위 저수준 IR 정의
- def-use 체인 생성
- SSA-like rename 도입
- constant/copy propagation
- stack slot alias 정리
- temporary value canonicalization
- `/json` 및 LLM prompt에 `ir_values` 전달

남은 고도화:

- block 간 reaching definition 전파
- memory alias와 stack-slot overlap 처리
- phi/merge 표현을 `value_merges`와 더 강하게 연결
- use-before-def / dead-store verifier rule 추가

기대 효과:

- 변수명/타입/조건식 품질 개선
- 동일 값의 여러 표현 통합
- verifier가 더 강한 검증 가능

#### 2) 고급 control-flow structuring

목표:

- if/else, while, do/while, switch, break/continue 패턴의 복구율 상승
- irreducible CFG나 비정형 흐름에서도 설명 가능한 출력 제공

구현됨:

- dominator 기반 natural loop 후보 식별
- 조건 block 기반 if/else 후보 식별
- 기존 switch 후보를 control-flow region으로 승격
- 구조 복구 실패 시 uncertainty 기록
- `/json` 및 LLM prompt에 `control_flow` 전달

남은 고도화:

- post-dominator 계산
- switch table / jump table case target 정밀 복구
- semantics-preserving structuring 도입
- iterative refinement 또는 fallback structuring 설계
- loop body 전체 closure와 exit/latch 정밀화
- break/continue 구분
- irreducible CFG 표시와 fallback evidence 품질 개선

기대 효과:

- pseudocode 가독성 대폭 향상
- loop/branch hallucination 감소

#### 3) x64 ABI / unwind / no-return 강화

목표:

- 현재 휴리스틱 기반 인자/로컬 복구를 ABI 지식과 unwind 정보로 보강

구현됨:

- shadow space / home slot 분석 강화
- prolog/epilog legal pattern 기반 프레임 인식 강화
- non-return 함수 탐지 및 수동 override 지원
- tail-call / thunk / import wrapper 분류
- `/json` 및 LLM prompt에 `abi` 전달
- fallback disassembly와 analyzer no-return 판단에 `DECOMP_NORETURN_OVERRIDES` 반영

남은 고도화:

- 실제 unwind metadata opcode 해석 심화
- epilog legal pattern 정밀화
- import wrapper와 일반 tail-call 구분 정확도 개선
- no-return override를 환경변수 외 WinDbg 명령으로 확장

기대 효과:

- 파라미터 개수와 역할 추정 정확도 향상
- 잘못된 block split, 잘못된 후속 control-flow 감소

### P1. 의미 복구 강화

상태:

- 2026-04-25 기준 P1 초기 구현 완료
- 새 analyzer facts: `type_hints`, `idioms`, `callee_summaries`
- PDB scoped params/locals, field hints, enum hints를 통합 type hint stream으로 승격
- symbol/type-enriched call target이 초기 callee summary를 대체하도록 연결
- README 반영 완료

남은 방향:

- 현재 구현은 "LLM이 바로 사용할 수 있는 의미 facts를 구조화해 전달하는 1차 기반"이다.
- 다음 단계는 DIA 기반 심화 타입 브라우징, 더 정교한 alias/type propagation, idiom signature DB, callee summary cache persistence다.

#### 4) 타입 복구 계층 강화

목표:

- PDB가 있을 때는 최대한 활용하고, PDB가 없을 때도 의미 있는 타입 힌트 제공

구현됨:

- 포인터/배열/구조체 field offset 전파
- enum-like 비교와 bitflag 패턴 분리
- class/vtable/RTTI 후보 수집
- 함수 시그니처 추정 결과의 confidence 구분
- PDB scoped params/locals/fields/enums를 `type_hints`로 승격
- `/json` 및 LLM prompt에 `type_hints` 전달

남은 고도화:

- DIA SDK 기반 심화 타입 브라우징 검토
- 구조체 field offset alias 정밀화
- class/vtable/RTTI 후보 confidence 개선
- type hint conflict resolver 추가

기대 효과:

- field access, enum 비교, helper call 설명력 상승
- LLM이 `UNKNOWN_TYPE`를 남발하는 빈도 감소

#### 5) Idiom / Outlining / Library pattern 인식

목표:

- 저수준 명령열을 더 높은 의미의 연산으로 치환

구현됨:

- memcpy/memset/strcpy 류 패턴 인식
- security cookie / stack probe / CRT helper 패턴 분류
- string initializer, array initializer 패턴 인식
- import / IAT / thunk / stub labeling 강화
- 표준 라이브러리 및 흔한 helper signature 데이터 축적
- symbol-resolved call target 기반 idiom 보강
- `/json` 및 LLM prompt에 `idioms` 전달

남은 고도화:

- 더 넓은 CRT/STL/Win32 helper signature DB
- inline memcpy/memset loop recognition
- string/array initializer range recovery
- thunk/import wrapper와 callee summary 간 상호 보정

기대 효과:

- pseudocode가 "무엇을 하는지" 바로 읽히는 수준으로 개선

#### 6) 인터프로시저 요약

목표:

- 호출 대상의 반환형, 부작용, ownership, 메모리 영향 등을 더 잘 설명

구현됨:

- direct call site 기반 초기 summary 생성
- known helper side-effect table
- import/API 이름 기반 semantic summary
- WinDbg symbol/type-enriched `CallTargetInfo`로 return type, parameter model, side effect, memory effect, ownership 갱신
- `/json` 및 LLM prompt에 `callee_summaries` 전달

남은 고도화:

- persistent direct callee summary cache
- intra-module callee 재분석 결과 재사용
- import API semantic table 확대
- ownership transfer 모델 세분화

기대 효과:

- 호출 중심 함수의 설명력 향상
- LLM 프롬프트 길이 대비 정보 밀도 증가

### P2. LLM 품질과 안정성 강화

상태:

- 2026-04-25 기준 P2 초기 구현 완료
- 새 prompt facts: `analyzer_skeleton`, `graph_summary`
- single-pass/chunk/merge prompt가 refine-first와 graph-aware 정책을 명시
- verifier가 branch/return/evidence coverage/suspicious identifier claim까지 추가 점검
- README 반영 완료

#### 7) refine-first 전략으로 전환

목표:

- "처음부터 새로 쓰는" 방식보다 analyzer output을 보정하는 방식 강화

구현됨:

- analyzer-only pseudo skeleton 품질 개선
- skeleton + evidence + uncertainty 기반 refinement prompt 도입
- mock/no-LLM path도 analyzer skeleton을 사용하도록 개선
- single-pass와 merge prompt에 skeleton refinement 규칙 추가

남은 고도화:

- 명시적인 `/refine` 모드 분리
- single-pass / chunked / refinement 모드의 사용자 노출 정책 정리
- 후보 다중 생성 후 verifier 점수 선택
- verifier feedback 기반 자동 재시도/refine loop

기대 효과:

- logical hallucination 감소
- 일관성 있는 출력 형식 확보

#### 8) graph-aware prompting

목표:

- CFG, loop, condition, call summary를 계층적으로 전달해 LLM의 구조 인식을 보조

구현됨:

- `graph_summary`에 entry, region, normalized condition, representative blocks 제공
- representative high-signal block 요약을 graph-aware prompt에 포함
- truncated input에 대한 명시적 불확실성 정책 강화
- single-pass/chunk/merge prompt에서 unsupported loop/switch/branch 생성 금지

남은 고도화:

- block tree / loop tree / region tree 설계
- block importance ranking 정량화
- evidence coverage 기반 merge 단계 자동 보정
- graph summary snapshot 회귀 테스트

기대 효과:

- 큰 함수, 최적화된 함수에서 품질 안정화

#### 9) verifier 확장

목표:

- 현재 schema/evidence/basic sanity check에서 더 나아가 의미 검증 강화

구현됨:

- branch claim vs CFG consistency 검사
- branch target expression과 CFG edge의 정밀 대응 검사
- variable use-before-def 스타일 검사
- loop claim vs back-edge + latch 검사
- switch claim vs switch evidence 검사
- no-return claim vs ABI no-return evidence 검사
- call/return behavior sanity 검사
- callee summary와 pseudo call effect 일관성 검사
- confidence scoring 세분화
- high-confidence response의 missing evidence 점검
- suspicious identifier/use-before-def 스타일 경고
- verifier warning별 severity/code 분리
- verifier feedback을 LLM retry prompt에 자동 반영

남은 고도화:

- verifier issue code별 snapshot 테스트 추가
- retry/refine 후보 다중 생성과 verifier 점수 기반 선택
- observed runtime evidence와 verifier rule 연결

기대 효과:

- 사용자가 결과를 더 신뢰할 수 있음
- 향후 auto-refine 루프의 품질 게이트로 활용 가능

### P3. WinDbg 사용자 편의성 강화

상태:

- 2026-04-25 기준 P3 초기 구현 완료
- DML-aware 출력에서 entry/basic block/evidence/call target 링크 제공
- 통합 출력 모드: `/view:brief|explain|json|facts|prompt|data|analyzer`
- 통합 캐시 재사용 모드: `/last:json|data|prompt`
- 통합 크기/한도 모드: `/limit:deep|huge|N`
- 통합 사용자 보정 명령: `/fix:noreturn:`, `/fix:type:`, `/fix:field:`, `/fix:rename:`, `/fix:clear`
- 진행 상태 추적 모드: `/verbose`
- 기본/brief/explain 출력에서 compact progress stream 제공
- Ctrl+Break 기반 장시간 `!decomp` 실행 취소
- 기존 개별 출력/캐시/보정 스위치는 호환 alias로 유지
- DML action row와 `/last:data`, `/last:prompt` 캐시 출력 추가
- DML action row의 `explain/json/facts/prompt/data-model` 링크를 재분석 없는 `/last:*` 캐시 출력으로 전환
- `/verbose`에서 target resolve, range recovery, disassembly, analyzer facts, LLM HTTP 요청/응답, retry, verifier 단계 로그 출력
- `/verbose`가 아니어도 local-analysis 완료, LLM chunk 진행률, retry/merge/verifier 상태를 최소 출력
- LLM 호출 대기 중 Ctrl+Break 감지 시 worker cancellation flag와 `CancelSynchronousIo`로 중단 요청
- `/fix:type:`, `/fix:field:`, `/fix:rename:` 세션 지속 보정 캐시 추가
- README 반영 완료

남은 방향:

- 현재 구현은 "WinDbg 출력에서 바로 점프하고, facts/prompt를 분리해서 볼 수 있는 1차 UX 기반"이다.
- 다음 단계는 실제 IDebugHost data model provider, JavaScript command bridge, TTD query 실행이다.

#### 10) DML 기반 탐색형 출력

목표:

- 출력이 단순 텍스트가 아니라 탐색 가능한 분석 화면 역할을 하도록 개선

작업:

- basic block 링크 구현됨
- call target 클릭 이동 구현됨
- entry disasm / bp 링크 구현됨
- DML action row에서 `/view:explain|json|facts|prompt|data` 전환 링크 구현됨
- DML nav row에서 entry disasm, entry breakpoint, `/last:json|data|prompt` 재사용 링크 구현됨
- evidence 항목에서 관련 block로 이동 구현됨
- control-flow region의 header/body/latch/exit block 탐색 링크 구현됨
- type hint site와 observed memory hotspot site 탐색 링크 구현됨
- uncertainty/verifier warning 항목에서 loop/switch/branch/no-return/return/function-entry 근거 위치로 이동 구현됨
- TTD query suggestion은 DML 링크로 바로 실행 가능하게 연결됨
- "dx 조회" 우클릭 메뉴는 실제 data model provider 연동 단계에서 고도화 예정

기대 효과:

- command output 자체가 mini UI 역할 수행
- 학습 비용 감소

#### 11) 데이터 모델 노출

목표:

- `!decomp` 결과를 `dx`, NatVis, JavaScript에서도 재활용 가능하게 제공

작업:

- `/view:data`로 안정적인 JSON snapshot 출력 구현됨
- `/last:data`로 최근 snapshot 재사용 구현됨
- 기존 `/data-model`, `/dx`, `/last-data-model`, `/last-dx`는 호환 alias로 유지
- request/response JSON과 block/instruction/type/idiom/callee/uncertainty 카운트를 함께 노출
- NatVis/JavaScript automation에서 재사용하기 쉬운 v1 object shape 초안 설계됨
- 실제 IDebugHost 기반 data model object 등록은 후속 고도화 예정
- JavaScript automation에서 직접 접근 가능한 provider API는 후속 고도화 예정

기대 효과:

- 확장 생태계 연계
- 후속 자동화와 시각화 기반 마련

#### 12) 사용자 보정 명령

목표:

- 분석 실패 원인을 사용자가 직접 좁혀갈 수 있도록 지원

작업:

- `/fix:noreturn:` no-return override 구현됨
- `/fix:type:` type hint override 구현됨
- `/fix:field:` field hint 추가 구현됨
- `/fix:rename:` rename/relabel 구현됨
- `/fix:type:`, `/fix:field:`, `/fix:rename:` 세션 지속 correction cache 구현됨
- 기본 실행 자체가 현재 facts로 재분석하며, `/last:json`으로 이전 결과 확인 가능
- `/fix:clear`로 session correction flush 구현됨
- 기존 `/noreturn:`, `/type:`, `/field:`, `/rename:`, `/clear-overrides`는 호환 alias로 유지

기대 효과:

- PDB가 약한 환경에서도 실사용성 향상

#### 13) 결과 모드 분리

목표:

- 서로 다른 사용 목적에 맞춘 출력 제공

작업:

- `/view:brief`: 빠른 요약 구현됨
- `/view:explain`: evidence 중심 설명 구현됨
- `/view:json`: 외부 도구용 구조화 출력 유지 및 P0/P1/P2/P3 facts와 호환
- `/view:prompt`: 프롬프트 진단 구현됨
- `/last:prompt`: 최근 프롬프트 덤프 재사용 구현됨
- `/view:facts`: analyzer 결과만 표시 구현됨
- 기존 개별 출력 스위치는 호환 alias로 유지

기대 효과:

- 초급자와 숙련자 모두에게 유용

### P4. WinDbg 고유 강점 활용

상태:

- 2026-04-25 기준 P4 초기 구현 완료
- 새 analyzer facts: `session_policy`, `observed_behavior`
- live/dump/kernel/TTD-like 세션 정책 분리
- 현재 디버거 컨텍스트의 `rip`, `rsp`, return address, x64 register argument sample 수집
- 반복 memory access hotspot 요약과 TTD query suggestion 제공
- README 반영 완료

남은 방향:

- 현재 구현은 "정적 facts에 WinDbg 세션/현재 프레임 관찰값을 병합하는 1차 기반"이다.
- 다음 단계는 실제 TTD call table 질의 실행, trace에서 인수/반환값 샘플링, 시간 구간별 memory write hotspot, observed evidence verifier rule이다.

#### 14) TTD 연동 분석

목표:

- 정적 분석이 애매한 지점을 trace 기반 사실로 보강

작업:

- TTD runtime/extension loaded 여부 기반 trace-like 세션 감지 구현됨
- 특정 함수 호출 이력 확인용 `dx @$cursession.TTD.Calls(...)` query suggestion 구현됨
- 현재 프레임의 x64 register argument sample 수집 구현됨
- 정적 memory access 기반 hotspot 요약 구현됨
- `/explain`, `/json`, prompt facts에 `observed_behavior` 섹션 추가됨
- 실제 TTD query 실행과 반환값/상태 플래그 변화 추적은 후속 고도화 예정

기대 효과:

- 정적 디컴파일러 대비 차별화
- API-heavy / state-machine 함수 해석력 향상

#### 15) live session / dump / trace 별 정책 분리

목표:

- 디버깅 모드별 특성을 반영한 분석 전략 제공

작업:

- live session: 빠른 정적 분석 + 현재 프레임 관찰값 우선 정책 구현됨
- dump: 정적 facts와 현재 context sample만 보수적으로 사용하도록 정책 구현됨
- TTD: trace query suggestion을 facts로 병합하도록 구현됨
- kernel / user mode 별 notes와 pointer 해석 주의사항 구현됨

기대 효과:

- 환경에 맞는 일관된 품질

## 개발 단계 제안

### Phase 1. 분석 코어 강화

기간 목표:

- SSA-lite를 넘어서는 value tracking 기반 마련
- control-flow structuring 품질 향상
- ABI/unwind/no-return 강화

현재 상태:

- 1차 구현 완료
- `ir_values`, `control_flow`, `abi`가 analyzer-only, `/json`, LLM prompt, verifier 경로에 연결됨
- `DECOMP_NORETURN_OVERRIDES`로 no-return 수동 보정 기반 마련

완료 기준:

- analyzer confidence와 verifier warning 품질이 체감 개선
- `/no-llm` 출력만으로도 함수 구조가 더 잘 읽힘
- analyzer facts JSON snapshot 테스트 추가
- loop/switch/no-return 대표 샘플에서 verifier warning 회귀가 안정화됨

### Phase 2. 의미 계층 강화

기간 목표:

- 타입/필드/enum/helper 의미 복구 강화
- idiom/outlining 도입
- direct callee summary 축적

현재 상태:

- 1차 구현 완료
- `type_hints`, `idioms`, `callee_summaries`가 analyzer-only, `/json`, LLM prompt 경로에 연결됨
- PDB enrichment와 call target enrichment가 P1 facts를 보강함

완료 기준:

- 흔한 런타임/라이브러리 함수가 저수준 명령열보다 고수준 의미로 보임
- PDB rich/public/stripped 샘플별 type hint 품질 차이를 snapshot으로 비교 가능
- helper pattern과 callee summary가 verifier/prompt 회귀 테스트에서 안정화됨

### Phase 3. UX 통합

기간 목표:

- DML 탐색형 출력
- data model / JavaScript / NatVis 노출
- 사용자 보정 명령 추가

현재 상태:

- 1차 구현 완료
- DML 링크, `/view:*` 출력 모드, `/last:*` 캐시 재사용, `/fix:*` 사용자 correction 명령이 기본 `!decomp` 경로에 연결됨

완료 기준:

- WinDbg 안에서 "읽기 -> 검증 -> 점프 -> 재분석" 루프가 자연스러워짐

### Phase 4. 고급 LLM refinement

기간 목표:

- graph-aware prompting
- refinement-first 전략
- verifier feedback loop

현재 상태:

- 1차 구현 완료
- `analyzer_skeleton`과 `graph_summary`가 single-pass/chunk/merge LLM 경로에 연결됨
- verifier가 loop/switch/no-return 외 branch target/return/callee effect/evidence/identifier 위험까지 severity/code 기반 issue로 점검함
- verifier feedback이 single-pass/chunk merge LLM retry prompt에 자동 반영됨

완료 기준:

- 큰 함수와 최적화 함수의 일관성 향상
- hallucination 빈도 감소
- verifier feedback 기반 retry/refine loop 안정화

### Phase 5. TTD 차별화

기간 목표:

- 동적 사실과 정적 구조를 병합한 출력 제공

현재 상태:

- 1차 구현 완료
- `session_policy`와 `observed_behavior`가 `/json`, `/facts-only`, prompt facts, `/explain` 경로에 연결됨
- TTD가 로드된 환경에서 사용자가 바로 실행할 수 있는 query suggestion 제공

완료 기준:

- trace 기반 디컴파일 보조라는 차별점 확보

## 측정 지표

다음 지표를 지속적으로 수집해야 한다.

- 구조 복구율
- loop/switch 복구율
- no-return 탐지 정확도
- parameter/local/type hint 정확도
- verifier warning 발생률
- uncertainty 누락률
- LLM fallback 비율
- chunked 분석 성공률
- 사용자 수정 후 재분석 성공률
- TTD 연동 시 추가 정보 유용도

## 테스트 전략

### 기능 테스트

- ntdll / kernel32 / user32 등 시스템 DLL 대표 함수
- CRT helper
- switch-heavy 샘플
- loop-heavy 샘플
- tail-call / thunk 샘플
- PDB rich / public / stripped 샘플

### 회귀 테스트

- analyzer facts JSON snapshot
- `ir_values`, `control_flow`, `abi` snapshot
- `type_hints`, `idioms`, `callee_summaries` snapshot
- `analyzer_skeleton`, `graph_summary` snapshot
- verifier score snapshot
- prompt truncation 동작 검증
- chunk merge consistency 검증

### 실사용 테스트

- malware-style 비정형 CFG
- 게임/상용 프로그램의 optimized x64 함수
- private symbol 유무 비교
- TTD trace가 있는 케이스와 없는 케이스 비교

## 리스크

### 기술 리스크

- SSA/structuring 도입 시 구현 복잡도 급증
- 잘못된 구조화가 오히려 더 위험한 pseudocode를 만들 수 있음
- DIA / dbgeng / WinDbg data model 연동 범위가 커질수록 유지보수 비용 증가

### 제품 리스크

- LLM 결과가 좋아 보여도 사실과 어긋날 수 있음
- UX 기능이 많아질수록 명령 체계가 복잡해질 수 있음
- trace 기반 기능은 TTD 사용 환경에서만 가치가 큼

## 의사결정 원칙

다음 원칙을 유지한다.

1. 보기 좋은 코드보다 사실에 맞는 코드를 우선한다.
2. 구조 복구 실패는 과감히 uncertainty로 남긴다.
3. PDB와 동적 사실은 강한 힌트이지만, disassembly와 모순되면 무조건 우선하지 않는다.
4. 새로운 기능은 반드시 analyzer-only 경로에서도 가치가 있어야 한다.
5. WinDbg 안에서 바로 검증 가능한 UX를 우선한다.

## 다음 액션

즉시 시작할 작업은 아래 순서를 권장한다.

1. P0 analyzer facts JSON snapshot 테스트 추가
2. P1 semantic facts JSON snapshot 테스트 추가
3. P2 prompt/verifier snapshot 테스트 추가
4. post-dominator / region tree 기반 structuring 고도화
5. unwind metadata opcode 해석과 epilog pattern 정밀화
6. 실제 TTD call table 질의 실행 및 인수/반환값 샘플링
7. IDebugHost data model provider와 JavaScript bridge 검토

이 순서가 가장 적은 리스크로 가장 큰 품질 향상을 기대할 수 있다.
