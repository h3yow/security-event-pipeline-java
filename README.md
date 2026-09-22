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
mvn test                       # 运行全部测试（13 个用例）
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

- JVM 内按窗口键（`ruleId#version#groupKey#windowStart`）加锁串行化同窗口更新；
- 关联表 `window_event(rule_id, window_key, event_id)` 有**唯一约束**，采用“先查后插 + 约束兜底”，
  保证每个事件对每个窗口只贡献一次计数；
- 聚合计数与窗口-事件关联全部落库，**重启后继续累计**，不回退、不重复。

### 3.4 规则变更后历史判定依据可追溯

规则是版本化的：更新规则插入新版本行，旧版本行永久保留。窗口聚合与告警都记录命中时的
`ruleId + version`；告警还内嵌当时的**规则快照 JSON**（阈值、窗口、条件等）。
规则随后如何修改，历史告警展示的都始终是它被判定时的依据。
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

### 6.2 自动化测试（`mvn test`，共 14 个用例）

| 测试类 | 覆盖内容 |
| --- | --- |
| `NormalizerTest`（5） | 必填缺失、非法时间戳、时间戳越界、未知来源、正常归一化 |
| `PipelineIntegrationTest`（5） | **16 线程并发同一事件只接受 1 次**；**乱序事件窗口计数稳定且只建 1 警**；**迟到超宽限被拒（WINDOW_EXPIRED）且拒绝留痕、事件不落库**；**非法流转(422)与越权(403)被正确归类、状态不变**；相邻窗口命中在 dedup 间隔内合并为 1 条告警 |
| `RuleVersioningTest`（1） | 规则变更产生 v2、v1 保留；历史告警仍引用 v1 与阈值=4 的快照；新事件按 v2 判定 |
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

## 7. 配置项（`src/main/resources/application.properties`）

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `spring.datasource.url` | `jdbc:h2:file:./data/pipelinedb` | H2 文件库（重启不丢数据的基础） |
| `pipeline.max-clock-skew-seconds` | `86400` | 允许事件时间早于接入时刻的上限 |
| `pipeline.max-future-seconds` | `300` | 允许事件时间超前的上限 |
| 规则内 `windowSeconds / allowedLatenessSeconds / threshold / dedupSeconds` | — | 每规则独立配置 |
