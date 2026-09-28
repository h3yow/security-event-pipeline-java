package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.domain.RuleMatch;
import com.github.h3yow.securityeventpipelinejava.domain.recon.EventContribution;
import com.github.h3yow.securityeventpipelinejava.domain.recon.RepairResult;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliation;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliationReport;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
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
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
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
                                 WindowLockManager windowLockManager) {
        this.ruleRepository = ruleRepository;
        this.aggregateRepository = aggregateRepository;
        this.windowEventRepository = windowEventRepository;
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
        this.transitionRepository = transitionRepository;
        this.repairAuditRepository = repairAuditRepository;
        this.ruleService = ruleService;
        this.alertService = alertService;
        this.jsonService = jsonService;
        this.windowLockManager = windowLockManager;
    }

    // ------------------------------------------------------------------
    // 对账查询（只读）
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public WindowReconciliationReport reconcile(String ruleCode, Integer ruleVersion,
                                                String groupKey, String from, String to) {
        Instant fromInstant = parseBoundary(from, "from");
        Instant toInstant = parseBoundary(to, "to");
        List<RuleEntity> versions = resolveRuleVersions(ruleCode, ruleVersion);
        Set<Long> ruleIds = versions.stream().map(RuleEntity::getId).collect(Collectors.toSet());

        // 拉取相关时间范围内的已受理事件一次，供各窗口重算（窗口起点可能早于事件时间下界，
        // 因此下界回退一个最大窗口长度，保证不漏算）。
        long maxWindowSeconds = versions.stream().mapToLong(RuleEntity::getWindowSeconds).max().orElse(0L);
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

        Map<Long, RuleEntity> ruleById = versions.stream()
                .collect(Collectors.toMap(RuleEntity::getId, r -> r));
        List<WindowReconciliation> windows = aggregates.stream()
                .map(a -> reconcileWindow(a, ruleById.get(a.getRuleId()), events))
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
                                                 List<EventEntity> candidates) {
        String windowKey = encodeWindowKey(agg);
        // 实际：window_event 去重关联行
        List<WindowEventEntity> actualRows =
                windowEventRepository.findByRuleIdAndWindowKeyOrderByEventIdAsc(agg.getRuleId(), windowKey);
        Set<String> actualIds = actualRows.stream().map(WindowEventEntity::getEventId)
                .collect(Collectors.toCollection(TreeSet::new));

        // 预期：按当时规则版本对已受理事件重算
        Set<String> expectedIds = expectedEventIds(rule, agg, candidates);

        Set<String> missing = new TreeSet<>(expectedIds);
        missing.removeAll(actualIds);
        Set<String> orphan = new TreeSet<>(actualIds);
        orphan.removeAll(expectedIds);

        boolean shouldFire = expectedIds.size() >= rule.getThreshold();
        boolean alertMissing = shouldFire && agg.getMatchedAlertId() == null;
        boolean alertNotApplicable = !shouldFire && agg.getMatchedAlertId() != null;

        List<EventContribution> contributions = buildContributions(
                actualRows, actualIds, expectedIds, candidates);

        boolean countMismatch = agg.getCount() != actualIds.size() || agg.getCount() != expectedIds.size();
        boolean firingMismatch = agg.isFired() != shouldFire;
        boolean consistent = missing.isEmpty() && orphan.isEmpty()
                && !countMismatch && !firingMismatch && !alertMissing && !alertNotApplicable;

        return new WindowReconciliation(
                rule.getId(), rule.getRuleCode(), rule.getVersion(), agg.getGroupKey(),
                agg.getWindowStart(), Instant.ofEpochSecond(agg.getWindowStart()).toString(),
                agg.getWindowEnd(), Instant.ofEpochSecond(agg.getWindowEnd()).toString(),
                rule.getThreshold(), agg.getCount(), actualIds.size(), expectedIds.size(),
                agg.isFired(), shouldFire, agg.getMatchedAlertId(),
                consistent, countMismatch, firingMismatch, alertMissing, alertNotApplicable,
                List.copyOf(missing), List.copyOf(orphan), contributions);
    }

    /** 按当时规则版本，重算窗口应纳入的去重事件ID集合。 */
    private Set<String> expectedEventIds(RuleEntity rule, WindowAggregateEntity agg,
                                         List<EventEntity> candidates) {
        Set<String> ids = new TreeSet<>();
        for (EventEntity e : candidates) {
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

    private List<RuleEntity> resolveRuleVersions(String ruleCode, Integer ruleVersion) {
        if (ruleCode == null || ruleCode.isBlank()) {
            throw new PipelineException(RejectReason.MISSING_FIELD, "对账查询必须提供 ruleCode");
        }
        List<RuleEntity> versions = ruleService.history(ruleCode);
        if (versions.isEmpty()) {
            throw new PipelineException(RejectReason.RULE_NOT_FOUND, "规则不存在: " + ruleCode);
        }
        if (ruleVersion != null) {
            List<RuleEntity> exact = versions.stream()
                    .filter(r -> r.getVersion() == ruleVersion).toList();
            if (exact.isEmpty()) {
                throw new PipelineException(RejectReason.RULE_NOT_FOUND,
                        "规则 " + ruleCode + " 不存在版本 v" + ruleVersion);
            }
            return exact;
        }
        return versions;
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
    // 自愈（下一小步实现）
    // ------------------------------------------------------------------

    @Transactional
    public RepairResult repair(WindowRepairRequest request, String operator, String operatorRole) {
        // 骨架占位，下一步填充
        return null;
    }
}
