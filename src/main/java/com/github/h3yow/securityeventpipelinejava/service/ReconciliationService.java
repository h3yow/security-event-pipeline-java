package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.domain.RuleMatch;
import com.github.h3yow.securityeventpipelinejava.domain.WindowKey;
import com.github.h3yow.securityeventpipelinejava.domain.recon.EventContribution;
import com.github.h3yow.securityeventpipelinejava.domain.recon.RepairResult;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliation;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliationReport;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowRepairAction;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RepairAuditEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.exception.PipelineException;
import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.AlertTransitionRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RepairAuditRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.web.WindowRepairRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * 窗口对账与自愈服务。
 *
 * <h3>对账</h3>：对每个窗口做三方比对——
 * <ol>
 *   <li>{@code storedCount}：window_aggregate 当前统计值；</li>
 *   <li>{@code actualUniqueCount}：window_event 去重关联行数（实际参与判定的唯一事件）；</li>
 *   <li>{@code expectedCount}：按<b>当时的规则版本</b>对已受理事件重算，理论上应纳入的去重事件数。</li>
 * </ol>
 * 差异通过 missingEventIds（少算）/ orphanEventIds（多算）逐条列出，不只给总数。
 *
 * <h3>自愈</h3>：以已受理去重事件为权威收敛统计；达到阈值确保有告警、未达到不误报、
 * 已存在且仍适用的告警不重复创建/累计。按窗口加锁（与接入路径同一把锁，覆盖事务），
 * 可重复/并发触发，结果幂等一致，每次执行写 repair_audit 审计。
 */
@Service
public class ReconciliationService {

    private static final Logger log = LoggerFactory.getLogger(ReconciliationService.class);

    private final RuleRepository ruleRepository;
    private final WindowAggregateRepository aggregateRepository;
    private final WindowEventRepository windowEventRepository;
    private final EventRepository eventRepository;
    private final AlertRepository alertRepository;
    private final AlertTransitionRepository transitionRepository;
    private final RepairAuditRepository repairAuditRepository;
    private final RuleService ruleService;
    private final AlertService alertService;
    private final JsonService jsonService;
    private final WindowLockManager windowLockManager;
    private final TransactionTemplate transactionTemplate;

    public ReconciliationService(RuleRepository ruleRepository,
                                 WindowAggregateRepository aggregateRepository,
                                 WindowEventRepository windowEventRepository,
                                 EventRepository eventRepository,
                                 AlertRepository alertRepository,
                                 AlertTransitionRepository transitionRepository,
                                 RepairAuditRepository repairAuditRepository,
                                 RuleService ruleService,
                                 AlertService alertService,
                                 JsonService jsonService,
                                 WindowLockManager windowLockManager,
                                 PlatformTransactionManager transactionManager) {
        this.ruleRepository = ruleRepository;
        this.aggregateRepository = aggregateRepository;
        this.windowEventRepository = windowEventRepository;
        this.eventRepository = eventRepository;
        this.ruleService = ruleService;
        this.alertRepository = alertRepository;
        this.transitionRepository = transitionRepository;
        this.repairAuditRepository = repairAuditRepository;
        this.alertService = alertService;
        this.jsonService = jsonService;
        this.windowLockManager = windowLockManager;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    // ------------------------------------------------------------------
    // 对账查询（只读）
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public WindowReconciliationReport reconcile(String ruleCode, Integer ruleVersion,
                                                String groupKey, String from, String to) {
        Instant fromInstant = parseBoundary(from, "from");
        Instant toInstant = parseBoundary(to, "to");
        // 完整版本历史用于计算每个版本"生效到何时"（下一版本 createdAt）；
        // targets 才是本次查询限定的版本（指定 ruleVersion 时只有一个）。
        List<RuleEntity> history = resolveRuleHistory(ruleCode);
        List<RuleEntity> targets = ruleVersion == null
                ? history : filterExactVersion(history, ruleCode, ruleVersion);
        Set<Long> ruleIds = targets.stream().map(RuleEntity::getId).collect(Collectors.toSet());
        Map<Long, Instant> effectiveUntil = effectiveUntilByRuleId(history);

        // 拉取相关时间范围内的已受理事件一次，供各窗口重算（窗口起点可能早于事件时间下界，
        // 因此下界回退一个最大窗口长度，保证不漏算）。
        long maxWindowSeconds = targets.stream().mapToLong(RuleEntity::getWindowSeconds).max().orElse(0L);
        Instant scanFrom = fromInstant == null ? null : fromInstant.minusSeconds(maxWindowSeconds);
        List<EventEntity> events = scanEvents(scanFrom, toInstant);

        List<WindowAggregateEntity> aggregates = aggregateRepository.findAll().stream()
                .filter(a -> ruleIds.contains(a.getRuleId()))
                .filter(a -> groupKey == null || groupKey.equals(a.getGroupKey()))
                .filter(a -> fromInstant == null || a.getWindowStart() >= fromInstant.getEpochSecond())
                .filter(a -> toInstant == null || a.getWindowStart() < toInstant.getEpochSecond())
                .sorted(Comparator.comparingLong(WindowAggregateEntity::getRuleId)
                        .thenComparingInt(WindowAggregateEntity::getVersion)
                        .thenComparing(WindowAggregateEntity::getGroupKey)
                        .thenComparingLong(WindowAggregateEntity::getWindowStart))
                .toList();

        Map<Long, RuleEntity> ruleById = targets.stream()
                .collect(Collectors.toMap(RuleEntity::getId, r -> r));
        List<WindowReconciliation> windows = aggregates.stream()
                .map(a -> reconcileWindow(a, ruleById.get(a.getRuleId()), events, effectiveUntil))
                .toList();

        long inconsistent = windows.stream().filter(w -> !w.consistent()).count();
        log.info("窗口对账: ruleCode={}, version={}, group={}, 窗口数={}, 不一致={}",
                ruleCode, ruleVersion, groupKey, windows.size(), inconsistent);
        return new WindowReconciliationReport(
                ruleCode, ruleVersion, groupKey,
                fromInstant == null ? null : fromInstant.toString(),
                toInstant == null ? null : toInstant.toString(),
                windows.size(), inconsistent, windows);
    }

    /** 计算单个窗口的三方对账结果。 */
    private WindowReconciliation reconcileWindow(WindowAggregateEntity agg, RuleEntity rule,
                                                 List<EventEntity> candidates,
                                                 Map<Long, Instant> effectiveUntil) {
        String windowKey = encodeWindowKey(agg);
        // 实际：window_event 去重关联行
        List<WindowEventEntity> actualRows =
                windowEventRepository.findByRuleIdAndWindowKeyOrderByEventIdAsc(agg.getRuleId(), windowKey);
        Set<String> actualIds = actualRows.stream().map(WindowEventEntity::getEventId)
                .collect(Collectors.toCollection(TreeSet::new));

        // 预期：按当时规则版本、且仅取受理时刻该版本仍生效的事件重算
        Set<String> expectedIds = expectedEventIds(rule, agg, candidates, effectiveUntil);

        Set<String> missing = new TreeSet<>(expectedIds);
        missing.removeAll(actualIds);
        Set<String> orphan = new TreeSet<>(actualIds);
        orphan.removeAll(expectedIds);

        boolean shouldFire = expectedIds.size() >= rule.getThreshold();
        // 告警归属健康度：恰好"该有一条且关联正确"才算健康
        List<Long> containingAlerts = alertRepository.findAll().stream()
                .filter(a -> a.getRuleId() == rule.getId())
                .filter(a -> a.getWindowKeys().contains(windowKey))
                .map(AlertEntity::getId).sorted().toList();
        boolean linkedContains = agg.getMatchedAlertId() != null
                && containingAlerts.contains(agg.getMatchedAlertId());
        boolean alertMissing = shouldFire
                && (agg.getMatchedAlertId() == null || !linkedContains);
        boolean alertNotApplicable = !shouldFire && !containingAlerts.isEmpty();

        List<EventContribution> contributions = buildContributions(
                actualRows, actualIds, expectedIds, candidates);

        boolean countMismatch = agg.getCount() != actualIds.size() || agg.getCount() != expectedIds.size();
        boolean firingMismatch = agg.isFired() != shouldFire;
        // 多条告警同时包含同一窗口，或关联指向的告警不含本窗口，均属归属错位
        boolean alertLinkBroken = shouldFire
                ? (!linkedContains || containingAlerts.size() > 1)
                : !containingAlerts.isEmpty();
        boolean consistent = missing.isEmpty() && orphan.isEmpty()
                && !countMismatch && !firingMismatch && !alertLinkBroken;

        return new WindowReconciliation(
                rule.getId(), rule.getRuleCode(), rule.getVersion(), agg.getGroupKey(),
                agg.getWindowStart(), Instant.ofEpochSecond(agg.getWindowStart()).toString(),
                agg.getWindowEnd(), Instant.ofEpochSecond(agg.getWindowEnd()).toString(),
                rule.getThreshold(), agg.getCount(), actualIds.size(), expectedIds.size(),
                agg.isFired(), shouldFire, agg.getMatchedAlertId(),
                consistent, countMismatch, firingMismatch, alertMissing, alertNotApplicable,
                List.copyOf(missing), List.copyOf(orphan), contributions);
    }

    /**
     * 按当时规则版本，重算窗口应纳入的去重事件ID集合。
     *
     * <p>除"事件时间落在窗口 + 匹配规则 + 分组一致"外，还必须满足<b>版本归属</b>：
     * 事件受理时刻（ingestTime）该版本正在生效，即
     * {@code createdAt(version) <= ingestTime < createdAt(nextVersion)}。
     * 这样升级后才受理的事件不会进入旧版本窗口（反之亦然），旧窗口升级后保持稳定。
     */
    private Set<String> expectedEventIds(RuleEntity rule, WindowAggregateEntity agg,
                                         List<EventEntity> candidates,
                                         Map<Long, Instant> effectiveUntil) {
        Instant effectiveFrom = rule.getCreatedAt();
        Instant nextVersionAt = effectiveUntil.get(rule.getId());
        Set<String> ids = new TreeSet<>();
        for (EventEntity e : candidates) {
            Instant ingestTime = e.getIngestTime();
            if (ingestTime.isBefore(effectiveFrom)) {
                continue;
            }
            if (nextVersionAt != null && !ingestTime.isBefore(nextVersionAt)) {
                continue;
            }
            if (e.getEventTime().getEpochSecond() < agg.getWindowStart()
                    || e.getEventTime().getEpochSecond() >= agg.getWindowEnd()) {
                continue;
            }
            NormalizedEvent ne = toNormalized(e);
            RuleMatch match = WindowRuleMatcher.match(rule, ne, jsonService);
            if (match != null && match.groupKey().equals(agg.getGroupKey())) {
                ids.add(e.getEventId());
            }
        }
        return ids;
    }

    /**
     * 计算每个规则版本行"生效到何时"：同 ruleCode 内下一版本（version+1）的 createdAt；
     * 当前最新版本无上界（null）。版本生效区间按受理时刻解释为
     * {@code [createdAt(v), createdAt(v+1))}，边界（恰好相等）归属新版本。
     */
    private Map<Long, Instant> effectiveUntilByRuleId(List<RuleEntity> history) {
        Map<String, List<RuleEntity>> byCode = history.stream()
                .collect(Collectors.groupingBy(RuleEntity::getRuleCode));
        Map<Long, Instant> result = new java.util.HashMap<>();
        byCode.values().forEach(versions -> {
            List<RuleEntity> asc = versions.stream()
                    .sorted(Comparator.comparingInt(RuleEntity::getVersion)).toList();
            for (int i = 0; i < asc.size(); i++) {
                Instant until = i + 1 < asc.size() ? asc.get(i + 1).getCreatedAt() : null;
                result.put(asc.get(i).getId(), until);
            }
        });
        return result;
    }

    private List<EventContribution> buildContributions(List<WindowEventEntity> actualRows,
                                                       Set<String> actualIds, Set<String> expectedIds,
                                                       List<EventEntity> candidates) {
        Map<String, EventEntity> byId = candidates.stream()
                .collect(Collectors.toMap(EventEntity::getEventId, e -> e, (a, b) -> a));
        Set<String> union = new TreeSet<>();
        union.addAll(actualIds);
        union.addAll(expectedIds);
        List<EventContribution> result = new ArrayList<>();
        for (String eventId : union) {
            boolean inActual = actualIds.contains(eventId);
            boolean inExpected = expectedIds.contains(eventId);
            EventEntity e = byId.get(eventId);
            String eventTime = e == null ? null : e.getEventTime().toString();
            String category;
            boolean counted;
            String detail;
            if (inActual && inExpected) {
                category = "COUNTED";
                counted = true;
                detail = "已计入统计，且符合当时规则口径";
            } else if (inExpected) {
                category = "MISSING";
                counted = false;
                detail = "符合规则应纳入，但窗口缺少关联（少算）";
            } else {
                category = "ORPHAN";
                counted = true;
                detail = "存在窗口关联，但按当时规则口径不应纳入（多算）";
            }
            result.add(new EventContribution(eventId, eventTime, counted, category, detail));
        }
        return result;
    }

    private List<EventEntity> scanEvents(Instant from, Instant to) {
        if (from != null && to != null) {
            return eventRepository.findByEventTimeGreaterThanEqualAndEventTimeLessThanOrderByEventTimeAscEventIdAsc(from, to);
        }
        List<EventEntity> all = new ArrayList<>(eventRepository.findAll());
        all.removeIf(e -> (from != null && e.getEventTime().isBefore(from))
                || (to != null && !e.getEventTime().isBefore(to)));
        all.sort(Comparator.comparing(EventEntity::getEventTime).thenComparing(EventEntity::getEventId));
        return all;
    }

    /** 解析规则编码的完整版本历史（按版本号升序返回，便于计算生效区间）。 */
    private List<RuleEntity> resolveRuleHistory(String ruleCode) {
        if (ruleCode == null || ruleCode.isBlank()) {
            throw new PipelineException(RejectReason.MISSING_FIELD, "对账查询必须提供 ruleCode");
        }
        List<RuleEntity> versions = ruleService.history(ruleCode).stream()
                .sorted(Comparator.comparingInt(RuleEntity::getVersion))
                .toList();
        if (versions.isEmpty()) {
            throw new PipelineException(RejectReason.RULE_NOT_FOUND,
                    "规则不存在: " + ruleCode + "（当前库中没有该 ruleCode 的任何版本）");
        }
        return versions;
    }

    /** 从完整历史中取出指定版本；不存在则给出可解释的 404（列出可用版本）。 */
    private List<RuleEntity> filterExactVersion(List<RuleEntity> history,
                                                String ruleCode, int ruleVersion) {
        List<RuleEntity> exact = history.stream()
                .filter(r -> r.getVersion() == ruleVersion).toList();
        if (exact.isEmpty()) {
            String available = history.stream()
                    .map(r -> "v" + r.getVersion()).collect(Collectors.joining(", "));
            throw new PipelineException(RejectReason.RULE_NOT_FOUND,
                    "规则 " + ruleCode + " 不存在版本 v" + ruleVersion
                            + "；当前可用版本: " + available);
        }
        return exact;
    }

    private static Instant parseBoundary(String value, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        } catch (Exception e) {
            throw new PipelineException(RejectReason.INVALID_TIMESTAMP,
                    "参数 " + field + " 不是 ISO-8601 时间: " + value);
        }
    }

    private static String encodeWindowKey(WindowAggregateEntity agg) {
        return agg.getRuleId() + "#v" + agg.getVersion() + "#" + agg.getGroupKey()
                + "#" + agg.getWindowStart();
    }

    /** 已受理事件实体转回归一化事件（对账重算与实时检测共用匹配口径）。 */
    private NormalizedEvent toNormalized(EventEntity e) {
        Map<String, String> attributes = jsonService.readStringMap(e.getAttributesJson());
        return new NormalizedEvent(
                e.getEventId(),
                com.github.h3yow.securityeventpipelinejava.common.EventSource.valueOf(e.getSource()),
                e.getEventTime(), e.getIngestTime(),
                e.getActor(), e.getAction(), e.getTarget(), e.getSourceIp(),
                attributes, e.getRawPayload());
    }

    // ------------------------------------------------------------------
    // 自愈
    // ------------------------------------------------------------------

    /** 一次修复选中的窗口及其上下文（规则、候选事件）。 */
    private record RepairTarget(WindowAggregateEntity agg, RuleEntity rule,
                                List<EventEntity> candidates, WindowModel model,
                                Map<Long, Instant> effectiveUntil) {
    }

    /** 单个窗口在某个时刻的对账计算中间态（对账查询与自愈共用）。 */
    private record WindowModel(
            String windowKey,
            Set<String> actualIds,
            Set<String> expectedIds,
            Set<String> missing,
            Set<String> orphan,
            boolean shouldFire,
            List<Long> containingAlertIds,
            List<EventEntity> windowEvents) {
        boolean consistent(long storedCount, boolean fired, Long alertId) {
            boolean linkedContains = alertId != null && containingAlertIds.contains(alertId);
            boolean alertLinkBroken = shouldFire
                    ? (!linkedContains || containingAlertIds.size() > 1)
                    : !containingAlertIds.isEmpty();
            return missing.isEmpty() && orphan.isEmpty()
                    && storedCount == expectedIds.size()
                    && actualIds.size() == expectedIds.size()
                    && fired == shouldFire
                    && !alertLinkBroken;
        }
    }

    public RepairResult repair(WindowRepairRequest request, String operator, String operatorRole) {
        WindowRepairRequest req = request == null
                ? new WindowRepairRequest(null, null, null, null, null, null, null) : request;
        String reason = req.triggerReason() == null || req.triggerReason().isBlank()
                ? "运维发起窗口自愈" : req.triggerReason();
        boolean onlyInconsistent = req.onlyInconsistent() == null || req.onlyInconsistent();

        Instant fromInstant = parseBoundary(req.from(), "from");
        Instant toInstant = parseBoundary(req.to(), "to");

        // 选择规则版本：未指定 ruleCode 时覆盖全部规则（用于全局收敛）。
        // 指定 ruleCode 时加载完整历史（用于计算版本生效区间），再按 ruleVersion 过滤目标。
        Map<Long, Instant> effectiveUntil;
        List<RuleEntity> versions;
        if (req.ruleCode() == null || req.ruleCode().isBlank()) {
            versions = ruleRepository.findAll();
            effectiveUntil = effectiveUntilByRuleId(versions);
        } else {
            List<RuleEntity> history = resolveRuleHistory(req.ruleCode());
            effectiveUntil = effectiveUntilByRuleId(history);
            versions = req.ruleVersion() == null
                    ? history : filterExactVersion(history, req.ruleCode(), req.ruleVersion());
        }
        Set<Long> ruleIds = versions.stream().map(RuleEntity::getId).collect(Collectors.toSet());
        long maxWindowSeconds = versions.stream().mapToLong(RuleEntity::getWindowSeconds).max().orElse(0L);
        Instant scanFrom = fromInstant == null ? null : fromInstant.minusSeconds(maxWindowSeconds);
        List<EventEntity> events = scanEvents(scanFrom, toInstant);

        Map<Long, RuleEntity> ruleById = versions.stream()
                .collect(Collectors.toMap(RuleEntity::getId, r -> r));

        // 先在事务外（只读短事务）选出目标窗口，拿到稳定的窗口键集合用于加锁
        List<RepairTarget> targets = selectTargets(
                ruleById, ruleIds, req.groupKey(), fromInstant, toInstant, events, effectiveUntil);
        List<String> windowKeys = targets.stream()
                .map(t -> t.model().windowKey).sorted().distinct().toList();

        log.info("窗口自愈开始: operator={}, 范围 ruleCode={}, version={}, group={}, [{},{}), 目标窗口数={}",
                operator, req.ruleCode(), req.ruleVersion(), req.groupKey(),
                req.from(), req.to(), targets.size());

        // 覆盖事务全程的窗口锁（与接入路径相同的锁），内部单事务收敛并写审计
        List<WindowRepairAction> actions = new ArrayList<>();
        long[] auditIdHolder = new long[1];
        int[] changedHolder = new int[1];
        windowLockManager.runLocked(windowKeys, () -> transactionTemplate.executeWithoutResult(status -> {
            // 锁内重新读取聚合并重算，避免选窗后发生漂移
            for (RepairTarget t : targets) {
                WindowAggregateEntity agg = aggregateRepository.findById(t.agg().getId()).orElse(null);
                if (agg == null) {
                    continue;
                }
                WindowModel model = computeModel(agg, t.rule(), t.candidates(), t.effectiveUntil());
                // onlyInconsistent 在锁内再次判定，保证与最新状态一致
                if (onlyInconsistent && model.consistent(
                        agg.getCount(), agg.isFired(), agg.getMatchedAlertId())) {
                    actions.add(noChange(t.rule(), agg, "窗口一致，无需修复"));
                    continue;
                }
                actions.add(repairWindow(agg, t.rule(), model));
            }
            changedHolder[0] = (int) actions.stream().filter(WindowRepairAction::changed).count();

            RepairAuditEntity audit = new RepairAuditEntity();
            audit.setTriggerReason(reason);
            audit.setOperator(operator);
            audit.setOperatorRole(operatorRole);
            audit.setScopeJson(jsonService.write(Map.of(
                    "ruleCode", req.ruleCode() == null ? "*" : req.ruleCode(),
                    "ruleVersion", req.ruleVersion() == null ? "*" : req.ruleVersion(),
                    "groupKey", req.groupKey() == null ? "*" : req.groupKey(),
                    "from", req.from() == null ? "*" : req.from(),
                    "to", req.to() == null ? "*" : req.to(),
                    "onlyInconsistent", onlyInconsistent)));
            audit.setScannedWindows(targets.size());
            audit.setChangedWindows(changedHolder[0]);
            audit.setActionsJson(jsonService.write(actions));
            audit.setCreatedAt(Instant.now());
            RepairAuditEntity saved = repairAuditRepository.save(audit);
            auditIdHolder[0] = saved.getId();
        }));

        log.info("窗口自愈完成: auditId={}, 扫描={}, 变更={}", auditIdHolder[0], targets.size(), changedHolder[0]);
        return new RepairResult(auditIdHolder[0], reason, operator,
                targets.size(), changedHolder[0], List.copyOf(actions));
    }

    private List<RepairTarget> selectTargets(Map<Long, RuleEntity> ruleById, Set<Long> ruleIds,
                                             String groupKey, Instant from, Instant to,
                                             List<EventEntity> events,
                                             Map<Long, Instant> effectiveUntil) {
        // 选中范围内全部窗口；是否一致在锁内用最新状态判定，保证 scannedWindows 反映真实扫描范围
        return transactionTemplate.execute(status -> aggregateRepository.findAll().stream()
                .filter(a -> ruleIds.contains(a.getRuleId()))
                .filter(a -> groupKey == null || groupKey.equals(a.getGroupKey()))
                .filter(a -> from == null || a.getWindowStart() >= from.getEpochSecond())
                .filter(a -> to == null || a.getWindowStart() < to.getEpochSecond())
                .sorted(Comparator.comparingLong(WindowAggregateEntity::getRuleId)
                        .thenComparingInt(WindowAggregateEntity::getVersion)
                        .thenComparing(WindowAggregateEntity::getGroupKey)
                        .thenComparingLong(WindowAggregateEntity::getWindowStart))
                .map(a -> new RepairTarget(a, ruleById.get(a.getRuleId()), events,
                        computeModel(a, ruleById.get(a.getRuleId()), events, effectiveUntil),
                        effectiveUntil))
                .toList());
    }

    /** 计算窗口实际/预期集合与差异（不写库）。 */
    private WindowModel computeModel(WindowAggregateEntity agg, RuleEntity rule,
                                     List<EventEntity> candidates,
                                     Map<Long, Instant> effectiveUntil) {
        String windowKey = encodeWindowKey(agg);
        List<WindowEventEntity> rows =
                windowEventRepository.findByRuleIdAndWindowKeyOrderByEventIdAsc(agg.getRuleId(), windowKey);
        TreeSet<String> actualIds = rows.stream().map(WindowEventEntity::getEventId)
                .collect(Collectors.toCollection(TreeSet::new));
        Set<String> expectedIds = expectedEventIds(rule, agg, candidates, effectiveUntil);
        List<EventEntity> windowEvents = candidates.stream()
                .filter(e -> expectedIds.contains(e.getEventId()))
                .sorted(Comparator.comparing(EventEntity::getEventTime).thenComparing(EventEntity::getEventId))
                .toList();
        TreeSet<String> missing = new TreeSet<>(expectedIds);
        missing.removeAll(actualIds);
        TreeSet<String> orphan = new TreeSet<>(actualIds);
        orphan.removeAll(expectedIds);
        boolean shouldFire = expectedIds.size() >= rule.getThreshold();
        List<Long> containingAlerts = alertRepository.findAll().stream()
                .filter(a -> a.getRuleId() == rule.getId())
                .filter(a -> a.getWindowKeys().contains(windowKey))
                .map(AlertEntity::getId).sorted().toList();
        return new WindowModel(windowKey, actualIds, expectedIds, missing, orphan,
                shouldFire, containingAlerts, windowEvents);
    }

    /** 在调用方事务与窗口锁内，收敛单个窗口到权威状态。 */
    private WindowRepairAction repairWindow(WindowAggregateEntity agg, RuleEntity rule, WindowModel m) {
        long countBefore = agg.getCount();
        boolean firedBefore = agg.isFired();
        Long alertBefore = agg.getMatchedAlertId();
        List<String> actionTypes = new ArrayList<>();
        List<String> added = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        List<String> notes = new ArrayList<>();

        // 1) 补齐缺失关联（少算）
        for (String eventId : m.missing()) {
            windowEventRepository.saveAndFlush(
                    new WindowEventEntity(rule.getId(), m.windowKey(), eventId));
            added.add(eventId);
        }
        if (!m.missing().isEmpty()) {
            actionTypes.add("ADDED_MEMBER");
            notes.add("补录缺失事件 " + m.missing());
        }
        // 2) 删除孤儿关联（多算）
        for (String eventId : m.orphan()) {
            windowEventRepository.deleteByRuleIdAndWindowKeyAndEventId(
                    rule.getId(), m.windowKey(), eventId);
            removed.add(eventId);
        }
        if (!m.orphan().isEmpty()) {
            actionTypes.add("REMOVED_ORPHAN");
            notes.add("移除不应纳入的关联 " + m.orphan());
        }

        // 3) 收敛统计值到权威去重事件数
        long correctCount = m.expectedIds().size();
        if (agg.getCount() != correctCount) {
            actionTypes.add("COUNT_CORRECTED");
            notes.add("统计值 " + agg.getCount() + " -> " + correctCount);
            agg.setCount(correctCount);
        }

        WindowKey windowKey = new WindowKey(rule.getId(), rule.getVersion(),
                agg.getGroupKey(), agg.getWindowStart());
        Long alertAfter = alertBefore;

        // 4) 阈值/告警收敛
        if (m.shouldFire()) {
            agg.setFired(true);
            if (firedBefore != agg.isFired()) {
                actionTypes.add("FIRED_CORRECTED");
            }
            Instant reference = m.windowEvents().isEmpty()
                    ? Instant.ofEpochSecond(agg.getWindowStart())
                    : m.windowEvents().get(m.windowEvents().size() - 1).getEventTime();
            AlertService.EnsureAlertResult ensured =
                    alertService.ensureAlertForWindow(rule, windowKey, agg, reference);
            alertAfter = ensured.alertId();
            if (ensured.created()) {
                actionTypes.add("FIRE_ALERT_CREATED");
            } else if (ensured.merged()) {
                actionTypes.add("FIRE_ALERT_MERGED");
            }
            if (!alertAfter.equals(alertBefore)) {
                // 关联为空时是补建/合并；关联非空但变了是错位改挂
                if (alertBefore != null) {
                    actionTypes.add("ALERT_RELINKED");
                }
                notes.add("告警关联 " + alertBefore + " -> " + alertAfter + "（" + ensured.note() + "）");
            } else if (ensured.created()) {
                notes.add("达到阈值但缺告警，补建告警 " + alertAfter);
            }
        } else {
            if (agg.isFired()) {
                agg.setFired(false);
                actionTypes.add("FIRED_CORRECTED");
                notes.add("实际未达阈值，撤销触发标记");
            }
            // 无论 matchedAlertId 是否为空，都检查是否有告警错误包含本窗口并解除
            AlertService.AlertClearResult clear =
                    alertService.clearAlertForWindow(windowKey, alertBefore);
            if (clear.alertId() != null || clear.deleted()) {
                if (clear.deleted()) {
                    actionTypes.add("FALSE_ALERT_DELETED");
                } else {
                    actionTypes.add("FALSE_ALERT_CLEARED");
                }
                if (clear.needsManualReview()) {
                    actionTypes.add("MANUAL_REVIEW_REQUIRED");
                }
                notes.add(clear.note());
            }
            agg.setMatchedAlertId(clear.deleted() ? null : clear.alertId());
            alertAfter = agg.getMatchedAlertId();
        }

        boolean changed = !actionTypes.isEmpty();
        if (!changed) {
            actionTypes.add("NO_CHANGE");
        }
        aggregateRepository.save(agg);

        WindowRepairAction action = new WindowRepairAction(
                m.windowKey(), rule.getRuleCode(), rule.getVersion(), agg.getGroupKey(),
                agg.getWindowStart(), changed, countBefore, correctCount,
                firedBefore, agg.isFired(), alertBefore, alertAfter,
                actionTypes, List.copyOf(added), List.copyOf(removed),
                String.join("；", notes));
        log.info("[自愈明细] window={}, actions={}, count {}->{}, fired {}->{}, alert {}->{}",
                m.windowKey(), actionTypes, countBefore, correctCount,
                firedBefore, agg.isFired(), alertBefore, alertAfter);
        return action;
    }

    private WindowRepairAction noChange(RuleEntity rule, WindowAggregateEntity agg, String note) {
        return new WindowRepairAction(
                encodeWindowKey(agg), rule.getRuleCode(), rule.getVersion(), agg.getGroupKey(),
                agg.getWindowStart(), false, agg.getCount(), agg.getCount(),
                agg.isFired(), agg.isFired(), agg.getMatchedAlertId(), agg.getMatchedAlertId(),
                List.of("NO_CHANGE"), List.of(), List.of(), note);
    }
}
