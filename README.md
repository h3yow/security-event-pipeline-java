# 安全事件检测流水线（Spring Boot）

把来自不同来源（防火墙 / 认证服务）的原始日志**归一化**为统一事件，基于事件时间窗口做**关联检测**，
并对命中结果进行**去重、合并、抑制**与**告警状态机**管理。异常输入不静默丢弃（全部审计留痕），
同一事件在并发/重试下只处理一次，服务重启后窗口计数与告警状态不丢失、不回退、不重复累计。

- Java 21 + Spring Boot 3.4 + Spring Data JPA + H2（文件库，零外部依赖，本地可直接运行）
- 全部状态（事件、拒绝记录、规则版本、窗口计数、告警、状态流转）持久化在 `./data/pipelinedb`

---

## 1. 快速开始

```bash
mvn spring-boot:run            # 或 mvn package && java -jar target/security-event-pipeline-1.0-SNAPSHOT.jar
# 服务监听 http://localhost:8080，首次启动自动写入 3 条演示规则
mvn test                       # 运行全部测试（27 个用例）
```

重置本地数据：停止服务后删除 `./data` 目录。

---

## 2. 原始日志接入格式

### `POST /api/events`

请求体：

```json
{
  "source": "FIREWALL | AUTH",
  "payload": { ...来源相关字段... }
}
```

成功响应（HTTP 200）：

```json
{ "accepted": true, "eventId": "evt-1", "rejection": null, "alertIds": [1] }
```

记录被拒绝（HTTP 400，原因在 `rejection.reason`；重复事件为 409 由全局异常体返回）：

```json
{ "accepted": false, "eventId": "evt-9",
  "rejection": { "reason": "MISSING_FIELD", "message": "缺少必填字段: srcIp" },
  "alertIds": [] }
```

### 2.1 FIREWALL（防火墙）

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `eventId` | 是 | 事件唯一ID，**幂等键** |
| `timestamp` | 是 | ISO-8601 时间，如 `2026-09-22T10:00:00Z` 或带偏移 `...T18:00:00+08:00` |
| `srcIp` | 是 | 来源 IP，归一化为 `sourceIp` |
| `action` | 是 | 动作（`ALLOW`/`DENY`…），归一化为 `action` |
| `target` | 是 | 目标，归一化为 `target` |
| `zone`、`bytes` | 否 | 进入扩展属性 `attributes` |

```bash
curl -X POST http://localhost:8080/api/events -H 'Content-Type: application/json' -d '{
  "source":"FIREWALL",
  "payload":{"eventId":"fw-1","timestamp":"2026-09-22T10:00:00Z",
             "srcIp":"10.0.0.1","action":"DENY","target":"10.0.0.9:22","zone":"dmz"}}'
```

### 2.2 AUTH（认证服务）

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `eventId` | 是 | 幂等键 |
| `timestamp` | 是 | ISO-8601 |
| `username` | 是 | 归一化为 `actor` |
| `result` | 是 | 归一化为 `action`，如 `LOGIN_FAIL` / `LOGIN_SUCCESS` |
| `service` | 是 | 归一化为 `target`，如 `ssh` |
| `srcIp` | 否 | 归一化为 `sourceIp` |

### 2.3 归一化规则与失败原因（可区分，绝不静默丢弃）

归一化后的统一事件字段：`eventId / source / eventTime(事件时间) / ingestTime(接入时间) /
actor / action / target / sourceIp / attributes / rawPayload`。

| reason（枚举） | 触发条件 | HTTP |
| --- | --- | --- |
| `MISSING_FIELD` | 必填字段缺失或空白；或缺少 `source` / `payload` | 400 |
| `ILLEGAL_FORMAT` | 字段类型非法（非标量）、请求体不是合法 JSON 等 | 400 |
| `INVALID_TIMESTAMP` | `timestamp` 不是 ISO-8601 可解析格式 | 400 |
| `TIMESTAMP_OUT_OF_RANGE` | 事件时间早于接入时刻超过 `pipeline.max-clock-skew-seconds`(默认 86400s)，或超前超过 `pipeline.max-future-seconds`(默认 300s) | 400 |
| `UNKNOWN_SOURCE` | `source` 不是 `FIREWALL`/`AUTH` | 400 |
| `DUPLICATE_EVENT` | 同一 `eventId` 已被接受处理（并发重试/重复提交） | 409 |
| `WINDOW_EXPIRED` | 事件时间所属检测窗口已关闭且超过规则允许的迟到宽限（拒绝留痕，事件不落库） | 400 |

每条拒绝都会写入 `rejected_event` 审计表（含原始报文、原因、明细、时间），可通过
`GET /api/audit/rejected` 查询。

### 2.4 “只处理一次”的实现

1. **JVM 内 eventId 分段锁**（64 段 ReentrantLock）：相同 eventId 串行、不同 eventId 并行，
   并在进入处理路径前用 `existsByEventId` 预检；
2. **数据库唯一约束** `accepted_event.uk_event_id`：多线程/多实例极端竞态下由数据库兜底，
   重复插入抛 `DataIntegrityViolationException` 并归类为 `DUPLICATE_EVENT`；
3. 重复提交返回 409，不产生第二条事件、不重复计数、不重复建警。

---

## 3. 时间窗口关联检测语义

### 3.1 规则

`POST /api/rules`（同一 `ruleCode` 再次提交会生成 **version+1** 的新版本，旧版本保留并停用）：

```json
{
  "ruleCode": "AUTH_BRUTE_FORCE",
  "name": "认证暴力破解",
  "matchConditions": { "action": "LOGIN_FAIL" },
  "groupBy": "actor",
  "windowSeconds": 60,
  "allowedLatenessSeconds": 120,
  "threshold": 3,
  "action": "ALERT",
  "dedupSeconds": 180,
  "enabled": true
}
```

- `matchConditions`：归一化字段（`source/actor/action/target/sourceIp` 或扩展属性）的
  **等值 AND** 匹配；
- `groupBy`：分组字段（如 `actor`、`sourceIp`），分组计数；空表示全局分组 `__GLOBAL__`；
- `action`：`ALERT`（产生 OPEN 告警）或 `SUPPRESS`（产生 SUPPRESSED 告警，即抑制）。

首次启动内置 3 条规则：`AUTH_BRUTE_FORCE`（60s 内同用户登录失败≥3）、
`FW_PORT_SCAN`（60s 内同源 IP DENY≥4）、`FW_NOISY_DENY`（≥10，抑制演示）。

### 3.2 窗口语义（乱序、迟到、时钟偏移下结论稳定）

- **滚动（tumbling）窗口，以事件时间对齐**：
  `windowStart = floor(eventTime.epochSecond / windowSeconds) * windowSeconds`。
  无论事件以什么顺序到达，只要事件时间落在同一个时间桶就计入同一窗口——
  乱序提交与顺序提交的判定结论完全一致。
- **迟到判定基于接入时刻墙上时钟（与处理顺序无关，重启后依旧成立）**：
  当 `now > windowEnd + allowedLatenessSeconds` 时拒绝该事件（`WINDOW_EXPIRED`，附窗口区间与规则宽限说明），
  事件不落库但拒绝留痕；仍在宽限内的迟到事件照常计入对应窗口。
- **时钟偏移**：事件时间超出全局容忍范围（默认早于现在 24h 或晚于现在 5min）在归一化阶段直接拒绝
  （`TIMESTAMP_OUT_OF_RANGE`），不会污染窗口。
- **触发**：窗口计数 `>= threshold` 即命中；**每个窗口最多触发一次**，之后同窗口的迟到/补发事件
  继续累加计数并关联到同一告警，但不会重复建警。

### 3.3 计数在并发下不重不漏

- JVM 内按窗口键（`ruleId#version#groupKey#windowStart`）加锁串行化同窗口更新，
  且**锁覆盖整个数据库事务直到提交**（接入与自愈共用同一把锁，见 {@link WindowLockManager}）：
  同一窗口几十条不同事件并发补录时，"读聚合→写关联→改计数"完全串行，
  不会出现聚合行唯一约束冲突或计数丢失更新；
- 关联表 `window_event(rule_id, window_key, event_id)` 有**唯一约束**，采用“先查后插 + 约束兜底”，
  保证每个事件对每个窗口只贡献一次计数；
- 聚合计数与窗口-事件关联全部落库，**重启后继续累计**，不回退、不重复。

### 3.4 规则变更后历史判定依据可追溯

规则是版本化的：更新规则插入新版本行，旧版本行永久保留。窗口聚合与告警都记录命中时的
`ruleId + version`；告警还内嵌当时的**规则快照 JSON**（阈值、窗口、条件等）。
规则随后如何修改，历史告警展示的都始终是它被判定时的依据。
事件按**受理时刻**归属当时生效的版本（`ingestTime ∈ [createdAt_v, createdAt_(v+1))`，见 8.1）：
升级只影响升级之后受理的事件；同一事件时间窗口里升级前后分别受理的事件进入各自版本的窗口，
旧版本窗口在升级后保持原样、不会被新事件抬高统计或触发告警。
查询：`GET /api/rules/{ruleCode}/history`、`GET /api/audit/windows`、告警详情中的
`ruleVersion` 与 `ruleSnapshotJson`。

---

## 4. 告警的去重、合并、抑制与状态机

### 4.1 去重与合并

同一规则、同一分组，在 `dedupSeconds` 间隔内的后续窗口命中会**合并进同一条活跃告警**：
`occurrenceCount +1`、窗口键追加进 `windowKeys`、刷新 `lastEventTime`，不另建告警；
超过间隔或没有活跃告警时才新建。`RESOLVED` 是终态，不会被重新打开（新命中产生新告警）。

### 4.2 抑制

规则 `action=SUPPRESS` 命中后创建的告警初始状态为 `SUPPRESSED`（仍完整记录、可后续处理）。

### 4.3 状态机

```
OPEN ──ACKNOWLEDGED──► ACKNOWLEDGED ──RESOLVED──► RESOLVED（终态）
  │                       ▲  │
  ├──SUPPRESSED──► SUPPRESSED ┘（ANALYST/ADMIN 可 ACK）
  │                  └──RESOLVED(ADMIN)──► RESOLVED
  └──RESOLVED(ADMIN/ANALYST)──► RESOLVED
ACKNOWLEDGED ──OPEN(ADMIN，退回)──► OPEN
RESOLVED ── 任何转换都被拒绝（ILLEGAL_STATE_TRANSITION, HTTP 422）
```

| 角色（`X-Operator-Role`） | 允许的转换 |
| --- | --- |
| `ADMIN` | 全部合法转换 |
| `ANALYST` | `→ACKNOWLEDGED`；`OPEN/ACKNOWLEDGED → RESOLVED` |
| `VIEWER` | 无（任何变更返回 403 `ACCESS_DENIED`） |

非法转换（含目标状态不存在、RESOLVED 回退）返回 422 `ILLEGAL_STATE_TRANSITION`，
消息中说明当前状态、目标状态与拒绝原因；越权返回 403 `ACCESS_DENIED`，状态不发生任何变化。
每次流转（含系统自动建警）都写 `alert_transition` 审计表。

`POST /api/alerts/{id}/transition`，请求头携带操作员信息（本地演示用，无鉴权框架）：

```bash
curl -X POST http://localhost:8080/api/alerts/1/transition \
  -H 'Content-Type: application/json' \
  -H 'X-Operator: alice' -H 'X-Operator-Role: ANALYST' \
  -d '{"targetStatus":"ACKNOWLEDGED","note":"开始处置"}'
```

---

## 5. HTTP 接口一览

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/events` | 接入原始日志（归一化 + 检测 + 告警） |
| `GET  /api/rules` | 列出全部规则版本 |
| `POST /api/rules` | 创建/更新规则（产生新版本） |
| `GET  /api/rules/{ruleCode}/history` | 规则版本历史（判定依据追溯） |
| `GET  /api/alerts` | 告警列表（含规则快照、窗口、聚合次数） |
| `POST /api/alerts/{id}/transition` | 告警状态流转（需 X-Operator[-Role] 头） |
| `GET  /api/audit/rejected` | 被拒绝记录审计（原因可区分） |
| `GET  /api/audit/windows` | 窗口聚合计数（判定依据） |
| `GET  /api/audit/windows/reconciliation` | **窗口对账**：三方比对 + 差异逐条列出（见第 8 节） |
| `POST /api/audit/windows/repair` | **窗口自愈**：按已受理去重事件收敛统计/阈值/告警（见第 8 节） |
| `GET  /api/audit/windows/repair/audits` | 自愈审计记录（何时/因何/处理了哪些窗口） |
| `GET  /api/audit/alerts/{id}/transitions` | 告警状态流转审计 |

---

## 6. 本地验证方法

### 6.1 端到端手工验证

```bash
mvn spring-boot:run
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# 阈值 3：连续 3 条登录失败，第 3 条响应 alertIds 非空
for i in 1 2 3; do
  curl -s -X POST localhost:8080/api/events -H 'Content-Type: application/json' \
    -d "{\"source\":\"AUTH\",\"payload\":{\"eventId\":\"d-$i\",\"timestamp\":\"$TS\",\"username\":\"mallory\",\"result\":\"LOGIN_FAIL\",\"service\":\"ssh\"}}"; echo
done
# 重复提交 => 409 DUPLICATE_EVENT
curl -i -X POST localhost:8080/api/events -H 'Content-Type: application/json' \
  -d "{\"source\":\"AUTH\",\"payload\":{\"eventId\":\"d-1\",\"timestamp\":\"$TS\",\"username\":\"mallory\",\"result\":\"LOGIN_FAIL\",\"service\":\"ssh\"}}"
# 缺字段 / 坏时间戳 => 400 且 reason 不同；随后可查审计
curl -s localhost:8080/api/audit/rejected
# 状态流转与越权
curl -X POST localhost:8080/api/alerts/1/transition -H 'X-Operator-Role: VIEWER' \
  -H 'Content-Type: application/json' -d '{"targetStatus":"ACKNOWLEDGED"}'   # 403
```

### 6.2 自动化测试（`mvn test`，共 27 个用例）

| 测试类 | 覆盖内容 |
| --- | --- |
| `NormalizerTest`（5） | 必填缺失、非法时间戳、时间戳越界、未知来源、正常归一化 |
| `PipelineIntegrationTest`（5） | **16 线程并发同一事件只接受 1 次**；**乱序事件窗口计数稳定且只建 1 警**；**迟到超宽限被拒（WINDOW_EXPIRED）且拒绝留痕、事件不落库**；**非法流转(422)与越权(403)被正确归类、状态不变**；相邻窗口命中在 dedup 间隔内合并为 1 条告警 |
| `ConcurrentBackfillTest`（2） | **50 条不同事件同窗口 16 线程并发补录：成功受理数=去重关联行=统计值=50，只建 1 警**；**40 不同事件 + 30 相同事件重试混合并发：受理 40、判重 30、计数 40** |
| `ReconciliationQueryTest`（2） | 健康窗口三方对账一致且贡献可解释；人为制造 count 漂移/缺失关联/孤儿关联时差异被逐条列出 |
| `WindowSelfHealTest`（4） | **修复收敛且重复触发幂等（0 变更、不重复建警、每次留审计）**；**未达阈值误报被删除且不会重建**；**8 并发修复仅第一次变更、最终一致**；跨分组错误并入的窗口归属被识别并解除（不误删真实告警） |
| `ReconciliationHttpApiTest`（1） | 对账/自愈/审计列表端点状态码与响应体；未知规则版本 404 |
| `RuleVersioningTest`（1） | 规则变更产生 v2、v1 保留；历史告警仍引用 v1 与阈值=4 的快照；新事件按 v2 判定 |
| `RuleVersionReconciliationTest`（4） | **升级前后同窗口事件按受理时刻各归各版本（计数/缺失/多余清单/告警状态全断言）**；**未知版本 404 与历史窗口升级后可查可修**；**升级与 60 路并发补录交叠 + 8 路并发自愈后各版本计数/触发/告警一致**；**恰好落在升级边界（+1µs）受理的事件归属唯一且贡献清单可解释** |
| `RestartPersistenceTest`（1） | 两个 Spring 上下文顺序启动同一文件库：ACK 状态与计数重启后保留；重放旧事件仍判重且计数不变；新事件继续累计并关联原告警 |
| `HttpApiTest`（1） | HTTP 层状态码/原因归类：400/409/403/422/404，响应体结构与审计端点 |
| `ApplicationTests`（1） | 上下文加载冒烟测试 |

测试日志中打印了 **输入事件**（`[输入事件]`）、**判定依据**（`[判定依据]`：匹配规则、窗口区间、
count/threshold/命中、拒绝原因）与**最终状态**（`[最终状态]`：计数、fired、告警状态），
例如：

```
[输入事件](乱序) {"source":"AUTH","payload":{...}}
窗口计数: eventId=ooo-3, rule=AUTH_BRUTE_FORCE#v1, group=bob,
  window=[...15:43:00Z,...15:44:00Z), count=3, threshold=3, 命中=true
[最终状态] 窗口 count=3, threshold=3, fired=true, alertId=1
```

查看某次测试的完整日志：`target/surefire-reports/...输出文件`，或直接观察 `mvn test` 控制台。

---

## 8. 窗口对账与自愈（运维）

面向运维的"判定结果是否可信"与"发现偏差后一键收敛"能力。对账只读取证、不改动数据；
自愈才会修改统计/告警，并对每次触发留审计。

### 8.1 对账查询 `GET /api/audit/windows/reconciliation`

查询参数（`ruleCode` 必填，其余可选）：

| 参数 | 说明 |
| --- | --- |
| `ruleCode` | 规则编码，如 `AUTH_BRUTE_FORCE` |
| `ruleVersion` | 限定**当时的规则版本**；不传则返回该规则全部版本的窗口（历史判定按各自版本重算） |
| `groupKey` | 限定分组（如 `actor` 的值 `mallory`）；不传则全部 |
| `from` / `to` | 窗口**起点**区间，ISO-8601，半开 `[from, to)`；不传不限 |

对每个窗口做**三方比对**，结果稳定（按规则/版本/分组/窗口起点排序、事件按 eventId 排序）：

- `storedCount`：`window_aggregate` 里当前统计值；
- `actualUniqueCount`：`window_event` 去重关联行数——**这次判定实际纳入的唯一事件数**；
- `expectedCount`：对已受理事件（`accepted_event`）按**窗口对应版本的规则口径**重新匹配/分桶，
  并且只保留**受理时刻（ingestTime）落在该版本生效区间**内的事件，得到的理论值。

#### 事件如何归属到规则版本（升级边界语义）

规则每次升级插入新版本行并记录 `createdAt`，版本 `v` 的生效区间为
**`[createdAt_v, createdAt_(v+1))`**（最后一个版本上界为 +∞，半开区间）。事件按
**受理时刻**而非事件时间归属：

- 升级**之前**受理、事件时间落在旧窗口的事件 → 只属于旧版本窗口；
- 升级**之后**才受理的事件（哪怕事件时间与旧窗口同一个 60s 桶）→ 只属于新版本窗口，
  **绝不会**出现在旧版本窗口的 `missingEventIds` 里，旧版本窗口升级后保持原样、稳定不变；
- 恰好等于边界受理（`ingestTime == createdAt_v2`）→ 按半开区间归属 **v2**，结果唯一。

差异不只给总数，而是逐条列出并给出布尔标记：

- `missingEventIds`（`MISSING`，少算：该版本生效期内受理、该纳入却没有关联行）、
  `orphanEventIds`（`ORPHAN`，多算：有关联行但按该版本受理时口径不该纳入）；
- `contributions[]`：并集内**每个事件**一行——`eventId / eventTime / counted / category / detail`，
  直接解释每个事件对统计的贡献。除 `COUNTED / MISSING / ORPHAN` 外还有：
  - **`EXCLUDED_OTHER_VERSION`**：事件时间虽落入本窗口、也符合本版本匹配条件，
    但受理时刻生效的是另一个规则版本——它归属对应版本窗口，在本版本**既不算缺失也不算多算**；
    `detail` 会带上该事件的受理时刻与边界解释，升级前后同窗口串账时一目了然；
- `countMismatch`（统计值与去重事件数对不上）、`firingMismatch`（fired 标记与阈值不符）、
  `alertMissing`（达到阈值却没有有效告警）、`alertNotApplicable`（未达阈值却挂着告警）；
- 顶层 `consistent` 与 `inconsistentWindows` 汇总。告警归属还会检查：
  关联的告警是否真包含本窗口键、是否有（甚至跨分组的）其它告警错误包含本窗口、是否多条告警重复包含。

```bash
curl 'http://localhost:8080/api/audit/windows/reconciliation?ruleCode=AUTH_BRUTE_FORCE&groupKey=mallory'
```

### 8.2 自愈 `POST /api/audit/windows/repair`

请求体（全部字段可选；空体表示对全部规则做一次全量收敛）：

```json
{
  "ruleCode": "AUTH_BRUTE_FORCE",
  "ruleVersion": 1,
  "groupKey": "mallory",
  "from": "2026-09-28T13:00:00Z",
  "to":   "2026-09-28T14:00:00Z",
  "onlyInconsistent": true,
  "triggerReason": "对账发现 count 与去重事件数不一致"
}
```

可带头 `X-Operator` / `X-Operator-Role`（仅记录到审计，不做权限拦截）。

**触发条件**：`onlyInconsistent` 默认 `true`，只修复对账不一致的窗口；设为 `false` 会对范围内
每个窗口都执行一次收敛（健康窗口动作为 `NO_CHANGE`，用于排障或强制对齐）。

**修复语义**（以"已受理的去重事件，按受理时生效版本归属"为权威，不重新校验迟到，不改 `accepted_event`）：

1. 按窗口对应版本的生效区间重算预期事件集（受理于其它版本的事件不参与），补齐 `MISSING`
   关联（`ADDED_MEMBER`）、删除 `ORPHAN` 关联（`REMOVED_ORPHAN`）；旧版本窗口不会把升级后
   受理的事件补进来，新版本窗口也不会挪用升级前的事件；
2. 把统计值收敛为预期去重事件数（`COUNT_CORRECTED`）；
3. 达到阈值：确保 `fired=true` 且存在一条**仍适用**的告警——
   优先复用已关联告警；关联错位时改挂到真正包含本窗口的告警；
   否则按实时检测相同的 dedup 合并口径并入活跃告警，都没有才补建（`FIRE_ALERT_CREATED`，
   流转操作人为 `system-heal`）。**已存在且仍适用的告警不会被重复创建或重复累计**；
4. 未达阈值：撤销 `fired`；解除告警对本窗口的归属并 `occurrenceCount-1`。
   若该告警因此不再关联任何窗口、且是未被人工处置过的纯自动告警（OPEN/SUPPRESSED、仅建警流转），
   则删除该误报告警及其流转（`FALSE_ALERT_DELETED`，修复审计另行留痕）；
   已被人工处置（ACK/RESOLVED 或有人工流转）的告警**不删除**，保留并标记
   `MANUAL_REVIEW_REQUIRED` 交运维处理，避免自愈抹掉人工记录。

返回 `RepairResult`：`auditId / triggerReason / operator / scannedWindows / changedWindows / actions[]`，
每个窗口一行 `WindowRepairAction`，含修复前后 `count/fired/alertId`、动作类型、
`addedEventIds/removedEventIds` 与文字说明。

**幂等与并发**：

- 可**重复触发**：第一次收敛后，后续执行对健康窗口 `NO_CHANGE`、`changedWindows=0`，
  统计、fired、告警数量与ID保持完全一致（不会二次建警/二次累计）；
- 可**并发触发**，也可与实时事件接入并发：自愈与接入共用同一把按窗口键的 JVM 锁，
  且**锁覆盖整个数据库事务直到提交**，多窗口按窗口键字典序加锁防死锁；
  锁内会重新读取候选事件并重算，因此多次（含并发）执行后结果收敛一致。审计每次触发都写一条
  （包括幂等空跑），可用 `GET /api/audit/windows/repair/audits` 查询；
- **规则升级与并发补录/重放交叠**：事件受理（读规则集→确定受理时刻→落库→窗口计数/建警）与
  规则版本发布由一把 JVM 部署读写锁互斥——受理持有读锁（彼此并行），升级持有写锁（事务提交
  后才放行新受理）。新版本 `createdAt` 由协调器单调生成，严格晚于任何已完成受理的
  `ingestTime`（至少 +1µs，规避数据库微秒截断）。因此：
  读锁期间受理的事件只可能命中旧版本，升级完成后受理的事件只可能命中新版本；
  每个事件只算进它受理时生效的那一个版本窗口，**不重不漏**；对账/自愈同样在读视图内执行，
  与升级不交叠，重复/并发执行后各版本窗口的计数、是否触发、关联告警完全一致。

**未知版本与历史可查**：查询/修复不存在的规则或版本返回 `404 RULE_NOT_FOUND`
（响应体给出 `message`，如"规则 X 不存在版本 v99"），不会返回空结果或自相矛盾；
已经落库的历史窗口与告警在升级后仍按其版本正常查看与修复。

> 部署说明：窗口锁与规则部署锁均为 JVM 内锁，与现有接入路径一致，适用于本项目的单实例 +
> H2 文件库部署；`window_event` 唯一约束在多实例极端竞态下继续兜底。

### 8.3 同窗口大量不同事件的并发补录/重放，以及与规则升级交叠

同一规则、同一分组、同一时间窗口允许几十条**不同**事件同时提交或从历史补入：
事件落库与该事件命中的全部窗口更新在同一个"窗口锁 + 单事务"内完成，
因此只要事件被成功受理，窗口最终去重事件数就与成功受理数**完全一致**（不少算、不重复算），
阈值触发与关联告警随之正确；相同事件的并发/重试依旧只受理一次（409 `DUPLICATE_EVENT`）。

规则升级与同一窗口的并发补录/重放交叠时，部署读写锁把"升级"与"受理"串行化，
配合单调的版本生效时刻，升级前后两个批次分别归入 v1 / v2 窗口（各算一次、不重不漏）；
升级后立刻对账，旧版本窗口保持原样，新版本窗口只包含升级后受理的事件。
该过程由 `RuleVersionReconciliationTest.concurrentBackfillInterleavedWithUpgradeAttributesEachEventExactlyOnce`
自动化覆盖（30 路升级前并发 + 升级 + 30 路升级后并发 + 8 路并发自愈）。

### 8.4 兼容范围（升级不清库）

- 只**新增**表 `repair_audit`，Hibernate `ddl-auto=update` 启动自动建表；
  既有 `accepted_event / window_event / window_aggregate / alert / alert_window /
  alert_transition / rejected_event / detection_rule` 表结构与数据均不变；
- 既有 `/api/events`、规则语义、告警状态机、原有审计端点保持不变；旧库升级后直接可用，
  无需清库或重导。对账/自愈读取的就是历史已落库数据与历史规则版本行。

### 8.5 本地复现

```bash
mvn spring-boot:run
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# 阈值 3：同窗口灌入事件（可用 seq + xargs -P 并发模拟几十条补录）
seq 1 50 | xargs -P 16 -I{} curl -s -X POST localhost:8080/api/events \
  -H 'Content-Type: application/json' \
  -d "{\"source\":\"AUTH\",\"payload\":{\"eventId\":\"bf-{}\",\"timestamp\":\"$TS\",\"username\":\"nick\",\"result\":\"LOGIN_FAIL\",\"service\":\"ssh\"}}"
# 对账：stored/actual/expected 三个数都应为 50，consistent=true
curl 'http://localhost:8080/api/audit/windows/reconciliation?ruleCode=AUTH_BRUTE_FORCE&groupKey=nick'
# 自愈（此时健康窗口 changedWindows=0，空跑也写审计）
curl -X POST localhost:8080/api/audit/windows/repair -H 'Content-Type: application/json' \
  -H 'X-Operator: ops1' -d '{"ruleCode":"AUTH_BRUTE_FORCE","groupKey":"nick"}'
curl localhost:8080/api/audit/windows/repair/audits
```

制造并修复不一致（演练，勿在生产直接改库）：在 H2 控制台/SQL 中删除某窗口一条
`window_event` 行并把 `window_aggregate.count` 改成别的值 → 对账出现 `missingEventIds` 与
`countMismatch=true` → 调 repair → 再对账 `consistent=true`，且重复 repair `changedWindows=0`。

**规则升级后按版本对账（本次修复的核心场景）**：

```bash
mvn spring-boot:run
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# 1) 先按旧版本（阈值 3）在当前窗口提交 3 条事件，达到阈值产生 1 条 v1 告警
for i in 1 2 3; do curl -s -X POST localhost:8080/api/events -H 'Content-Type: application/json' \
  -d "{\"source\":\"AUTH\",\"payload\":{\"eventId\":\"old-$i\",\"timestamp\":\"$TS\",\"username\":\"ada\",\"result\":\"LOGIN_FAIL\",\"service\":\"ssh\"}}"; done
# 2) 升级规则到新版本（阈值 5）
curl -s -X POST localhost:8080/api/rules -H 'Content-Type: application/json' \
  -d '{"ruleCode":"AUTH_BRUTE_FORCE","name":"认证暴力破解","matchConditions":{"action":"LOGIN_FAIL"},"groupBy":"actor","windowSeconds":60,"allowedLatenessSeconds":120,"threshold":5,"action":"ALERT","dedupSeconds":180,"enabled":true}'
# 3) 同一事件时间窗口里再按新版本提交 1 条（未达 v2 阈值 5，不应建警）
curl -s -X POST localhost:8080/api/events -H 'Content-Type: application/json' \
  -d "{\"source\":\"AUTH\",\"payload\":{\"eventId\":\"new-1\",\"timestamp\":\"$TS\",\"username\":\"ada\",\"result\":\"LOGIN_FAIL\",\"service\":\"ssh\"}}"
# 4) 对账：v1 窗口 expected=3、consistent=true（new-1 显示为 EXCLUDED_OTHER_VERSION，而不是 MISSING）
curl 'http://localhost:8080/api/audit/windows/reconciliation?ruleCode=AUTH_BRUTE_FORCE&groupKey=ada'
# 5) 自愈：changedWindows=0；v1 统计仍为 3、仍只关联原告警；v2 窗口 count=1、未触发、无告警
curl -s -X POST localhost:8080/api/audit/windows/repair \
  -H 'Content-Type: application/json' -H 'X-Operator: ops1' -d '{"ruleCode":"AUTH_BRUTE_FORCE","groupKey":"ada"}'
# 未知版本给出可解释的 404
curl -i 'http://localhost:8080/api/audit/windows/reconciliation?ruleCode=AUTH_BRUTE_FORCE&ruleVersion=99'
```

自动化复现（推荐，确定性、无需手搓时间点）：

```bash
mvn test -Dtest=RuleVersionReconciliationTest
# 4 个用例：端到端归属/对账/自愈、未知版本404+历史可查、升级与并发受理交叠、边界受理归属
```

---

## 9. 配置项（`src/main/resources/application.properties`）

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `spring.datasource.url` | `jdbc:h2:file:./data/pipelinedb` | H2 文件库（重启不丢数据的基础） |
| `pipeline.max-clock-skew-seconds` | `86400` | 允许事件时间早于接入时刻的上限 |
| `pipeline.max-future-seconds` | `300` | 允许事件时间超前的上限 |
| 规则内 `windowSeconds / allowedLatenessSeconds / threshold / dedupSeconds` | — | 每规则独立配置 |
