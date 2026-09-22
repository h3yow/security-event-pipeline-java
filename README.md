# Security Event Pipeline

本地可运行的安全事件检测流水线：多源日志接入 → 归一化 → 基于事件时间的窗口关联检测 → 告警去重/合并/抑制与状态流转。所有状态持久化于文件型 H2 数据库，服务重启后不丢失、不回退、不重复累计。

## 快速开始

```bash
# 运行测试（21 个用例，覆盖并发重复提交、乱序迟到、非法状态流转、重启持久化）
mvn test

# 本地启动（端口 8080，数据落盘 ./data/pipeline.mv.db）
mvn spring-boot:run
```

## 接入格式

`POST /api/logs`，请求体：

```json
{
  "source": "AUTH | FIREWALL | IDS",
  "eventId": "来源系统的事件唯一标识（幂等键，必填）",
  "payload": "原始报文（字符串，必填）"
}
```

三种来源的 payload 格式：

| source    | 格式                     | 必填字段                     | 可选字段 |
|-----------|--------------------------|------------------------------|----------|
| FIREWALL  | JSON 对象                | `ts`, `action`, `src_ip`     | `user`   |
| IDS       | JSON 对象                | `timestamp`, `signature`, `src` | `user` |
| AUTH      | `key=value` 空格分隔文本 | `ts`, `action`, `src_ip`     | `user`   |

时间戳支持 ISO-8601 字符串（如 `2026-09-22T10:00:00Z`）与 epoch 秒/毫秒数字。

示例：

```bash
curl -X POST http://localhost:8080/api/logs -H 'Content-Type: application/json' -d '{
  "source": "AUTH",
  "eventId": "e1",
  "payload": "ts=2026-09-22T10:00:01Z action=LOGIN_FAIL src_ip=10.0.0.1 user=alice"
}'
```

响应：接受 → `200 {"accepted":true,...}`；重复 → `200` 且 `reason=DUPLICATE`；拒绝 → `422` 且携带可区分原因。

## 归一化规则

所有来源归一化为统一模型 `NormalizedEvent`：`eventId / source / action / eventTime / receivedAt / groupKey(=源IP) / username / rawPayload`。

- IDS 的 `signature` 归一化为大写 `action`；`src`/`timestamp` 映射到统一字段。
- 分组键 `groupKey` 统一取源 IP，窗口关联按此分组。

**拒绝语义（不静默丢弃）**：任何被拒绝的记录都会持久化到 `rejected_event` 表（含原始报文与原因），并在响应中返回可区分原因：

| reason             | 含义                                                     |
|--------------------|----------------------------------------------------------|
| `MISSING_FIELD`    | eventId/source/payload 或报文必填字段缺失                |
| `INVALID_FORMAT`   | JSON 无法解析、key=value 词法错误                        |
| `INVALID_TIMESTAMP`| 时间戳无法解析、早于 2020-01-01、或超过当前时间 24h（时钟偏移容忍上限） |
| `TOO_LATE`         | 事件时间早于 `水位线 - 最大允许迟到`（见下节）            |
| `DUPLICATE`        | 同一 eventId 已处理过（幂等去重，不重复计数）             |

**幂等**：`eventId` 上有数据库唯一约束。并发重试/重复提交时，仅一个请求落库成功，其余得到 `DUPLICATE`，事件只被处理一次。

## 时间窗口语义

检测规则（`detection_rule` 表，版本化）字段：`action`、`windowSeconds`、`threshold`、`maxLatenessSeconds`、`enabled`。启动时播种两条规则：

- `BRUTE_FORCE_LOGIN`：同一源 IP 300s 内 `LOGIN_FAIL` ≥ 3 次
- `CONNECTION_STORM`：同一源 IP 60s 内 `CONNECTION_DENIED` ≥ 5 次

**窗口评估**：新事件 e 到达时，对每条匹配规则评估"锚点窗口"——以同分组内事件时间落在 `[e.eventTime, e.eventTime + window]` 的每个事件为右端点的窗口 `[anchor - window, anchor]`，统计窗口内同分组、同动作的事件数，达到阈值即触发。

- **基于事件时间**，与到达时间无关，乱序到达不改变结论。
- **迟到事件**：不仅评估自己的窗口，还补评它参与计数的更晚锚点窗口，因此迟到事件与正序到达得到一致结论。
- **水位线与最大迟到**：水位线 = 已见最大事件时间；事件时间早于 `水位线 - maxLatenessSeconds`（取各启用规则最大值）的记录以 `TOO_LATE` 拒绝。
- **时钟偏移**：未来 24h 内的时间戳被接受；超过则以 `INVALID_TIMESTAMP` 拒绝。
- **计数正确性**：计数由已持久化的唯一事件（eventId 去重）实时重算，并发提交不会重复或遗漏，重启后无需恢复任何内存状态。

**可追溯性**：每次触发将判定依据（规则 id、规则版本、窗口起止、计数、阈值、参与事件 id 列表）以 JSON 快照存入告警。规则变更产生新版本行，旧版本不再参与评估，但历史告警的判定依据保持原样，可随时回溯。

## 告警生命周期

**去重与合并**：告警指纹 = `ruleId | groupKey | 窗口桶`（事件时间对齐到窗口宽度）。同指纹的重复触发合并为一条告警：`hitCount` 累计、判定依据快照更新；并发创建由唯一约束 + 独立事务重试保证不丢不重。合并进终态（如 SUPPRESSED）告警不会改变其状态（抑制语义）。

**状态机**（非法流转 → `409 ILLEGAL_TRANSITION`；越权 → `403 FORBIDDEN_ROLE`；告警不存在 → `404 ALERT_NOT_FOUND`）：

```
OPEN ──ANALYST/ADMIN──> ACKNOWLEDGED ──ANALYST/ADMIN──> INVESTIGATING ──ANALYST/ADMIN──> RESOLVED
 │                          │                               │
 ├──ADMIN──> SUPPRESSED     ├──ADMIN──> SUPPRESSED          ├──ANALYST/ADMIN──> FALSE_POSITIVE
 └──ANALYST/ADMIN──> FALSE_POSITIVE                         └──ADMIN──> SUPPRESSED
（RESOLVED / SUPPRESSED / FALSE_POSITIVE 为终态，无出边）
```

每次成功流转写入 `alert_transition` 审计表（操作者角色、起止状态、时间、备注）。告警实体的乐观锁（`@Version`）保证并发流转只有一个成功。

**API**：

```bash
GET  /api/alerts                          # 告警列表（含判定依据快照）
GET  /api/alerts/{id}                     # 单条告警
GET  /api/alerts/{id}/transitions         # 流转审计历史
POST /api/alerts/{id}/transition          # 状态流转，请求头 X-Role: ANALYST|ADMIN
     {"target": "ACKNOWLEDGED", "note": "..."}
```

## 持久化与重启

默认使用文件型 H2（`./data/pipeline.mv.db`，`ddl-auto=update`）。事件、拒绝记录、规则、告警、流转审计全部落盘；窗口计数由持久化事件重算，无内存态需要恢复。重启后：未完成告警状态不回退、聚合计数不重复累计、幂等去重继续生效（由 `RestartPersistenceTest` 验证：连续启动两个 Spring 上下文共享同一库文件）。

## 本地验证方法

```bash
# 1. 单元/集成测试（日志会打印输入事件、窗口判定依据与最终状态）
mvn test

# 2. 端到端手动验证
mvn spring-boot:run &
# 触发暴力破解告警（5 分钟内 3 次 LOGIN_FAIL）
for i in 1 2 3; do
  curl -X POST localhost:8080/api/logs -H 'Content-Type: application/json' \
    -d "{\"source\":\"AUTH\",\"eventId\":\"e$i\",\"payload\":\"ts=2026-09-22T10:00:0${i}Z action=LOGIN_FAIL src_ip=10.0.0.1 user=alice\"}"
done
curl localhost:8080/api/alerts                       # 查看告警与判定依据快照
curl -X POST localhost:8080/api/alerts/1/transition \
  -H 'Content-Type: application/json' -H 'X-Role: ANALYST' \
  -d '{"target":"ACKNOWLEDGED","note":"taking it"}'
# 重启服务后再次访问，状态保持；重复提交 e1 返回 DUPLICATE
```

## 测试覆盖

| 测试类                          | 覆盖点                                                         |
|---------------------------------|----------------------------------------------------------------|
| `NormalizationIngestTest`       | 缺字段/非法格式/异常时间戳的可区分拒绝原因、拒绝留痕、多源归一化 |
| `ConcurrentDuplicateIngestTest` | 16 线程并发同一 eventId 只处理一次；多事件 x2 重试各计一次       |
| `WindowDetectionTest`           | 乱序触发、迟到合并、超迟到拒绝、窗口边界不计数、时钟偏移容忍     |
| `AlertStateMachineTest`         | 非法流转、越权角色、终态无出边、审计留痕、抑制不复活             |
| `RuleVersioningTest`            | 规则变更后历史告警判定依据（版本+快照）可追溯                    |
| `RestartPersistenceTest`        | 重启后状态不回退、去重仍生效、聚合不重复累计                     |
