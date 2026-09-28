package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.domain.StoredEventView;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.AlertBrief;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.ReconciliationQuery;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.WindowContribution;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.WindowReconciliationResult;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.exception.PipelineException;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import static com.github.h3yow.securityeventpipelinejava.common.RejectReason.RULE_NOT_FOUND;
/**
 * 窗口对账查询服务。
 *
 * <p>对每个已存在的窗口聚合，用<b>当时的规则版本快照</b>对“全部已受理事件”重新匹配，
 * 复算这个窗口<b>应当</b>纳入的去重事件集合，再与实际落库的 {@code window_event}
 * 关联和 {@code window_aggregate} 统计逐项对比：
 * <ul>
 *   <li>{@code uniqueEventCount}：按规则版本复算、事件时间落入该窗口且已受理的去重事件数；</li>
 *   <li>{@code storedCount}：window_aggregate 当前计数；</li>
 *   <li>{@code countDiff = storedCount - uniqueEventCount}，并给出 missing / unexpected 事件明细，
 *       不只是一个总数；</li>
 *   <li>{@code shouldFire / fired}：是否应达阈值与当前是否已触发的对比；</li>
 *   <li>{@code alert}：matchedAlertId 对应告警及实际携带该窗口键的告警。</li>
 * </ul>
 * 结果按窗口键字典序稳定返回，可解释、可复现。
 */
@Service
public class ReconciliationService {

    private static final Logger log = LoggerFactory.getLogger(ReconciliationService.class);

    private final WindowAggregateRepository aggregateRepository;
    private final WindowEventRepository windowEventRepository;
    private final EventRepository eventRepository;
    private final RuleRepository ruleRepository;
    private final AlertRepository alertRepository;
    private final RuleMatcher ruleMatcher;
    private final JsonService jsonService;

    public ReconciliationService(WindowAggregateRepository aggregateRepository,
                                 WindowEventRepository windowEventRepository,
                                 EventRepository eventRepository,
                                 RuleRepository ruleRepository,
                                 AlertRepository alertRepository,
                                 RuleMatcher ruleMatcher,
                                 JsonService jsonService) {
        this.aggregateRepository = aggregateRepository;
        this.windowEventRepository = windowEventRepository;
        this.eventRepository = eventRepository;
        this.ruleRepository = ruleRepository;
        this.alertRepository = alertRepository;
        this.ruleMatcher = ruleMatcher;
        this.jsonService = jsonService;
    }

    @Transactional(readOnly = true)
    public List<WindowReconciliationResult> reconcile(ReconciliationQuery q) {
        ReconciliationQuery query = q == null ? new ReconciliationQuery(null, null, null, null, null) : q;
        validateQuery(query);

        // 1. 筛出目标窗口聚合
        List<WindowAggregateEntity> aggregates = aggregateRepository.findAllByOrderByIdDesc().stream()
                .filter(a -> query.ruleCode() == null || ruleCodeOf(a.getRuleId()).equals(query.ruleCode()))
                .filter(a -> query.version() == null || a.getVersion() == query.version())
                .filter(a -> query.groupKey() == null || query.groupKey().equals(a.getGroupKey()))
                .filter(a -> query.windowStartFrom() == null || a.getWindowStart() >= query.windowStartFrom())
                .filter(a -> query.windowStartTo() == null || a.getWindowStart() <= query.windowStartTo())
                .sorted(Comparator
                        .comparing((WindowAggregateEntity a) -> ruleCodeOf(a.getRuleId()))
                        .thenComparingInt(WindowAggregateEntity::getVersion)
                        .thenComparing(WindowAggregateEntity::getGroupKey)
                        .thenComparingLong(WindowAggregateEntity::getWindowStart))
                .toList();

        // 2. 一次性载入全部已受理事件（本地 H2 规模可控），构建复算视图
        Map<String, EventEntity> eventsById = new LinkedHashMap<>();
        for (EventEntity e : eventRepository.findAll()) {
            eventsById.put(e.getEventId(), e);
        }

        // 3. 按规则版本缓存，避免重复解析
        Map<Long, RuleEntity> ruleCache = new LinkedHashMap<>();

        List<WindowReconciliationResult> results = new ArrayList<>();
        for (WindowAggregateEntity aggregate : aggregates) {
            RuleEntity rule = ruleCache.computeIfAbsent(aggregate.getRuleId(),
                    id -> ruleRepository.findById(id).orElse(null));
            results.add(reconcileOne(aggregate, rule, eventsById));
        }
        log.info("对账完成: 查询条件={}, 命中窗口数={}, 一致窗口数={}, 不一致窗口数={}",
                query, results.size(),
                results.stream().filter(WindowReconciliationResult::consistent).count(),
                results.stream().filter(r -> !r.consistent()).count());
        return results;
    }

    private WindowReconciliationResult reconcileOne(WindowAggregateEntity aggregate, RuleEntity rule,
                                                    Map<String, EventEntity> eventsById) {
        String windowKey = encodeWindowKey(aggregate);
        int threshold = aggregate.getThreshold();
        long windowStart = aggregate.getWindowStart();
        long windowEnd = aggregate.getWindowEnd();
        String ruleCode = rule == null ? null : rule.getRuleCode();

        // 3.1 实际参与判定（已落库 window_event）的去重事件
        Set<String> linked = new TreeSet<>();
        for (WindowEventEntity link : windowEventRepository.findByWindowKeyOrderByEventIdAsc(windowKey)) {
            linked.add(link.getEventId());
        }

        // 3.2 按规则版本快照对全部已受理事件复算：匹配 + 事件时间落入窗口
        Set<String> expected = new TreeSet<>();
        List<WindowContribution> contributions = new ArrayList<>();
        if (rule != null) {
            for (EventEntity event : eventsById.values()) {
                long t = event.getEventTime().getEpochSecond();
                if (t < windowStart || t >= windowEnd) {
                    continue;
                }
                // 事件必须是在该规则版本生效期间受理的：升级后受理的事件不“穿越”进旧版本窗口
                if (!acceptedWhileVersionActive(rule, event)) {
                    continue;
                }
                Map<String, String> attrs = jsonService.readStringMap(event.getAttributesJson());
                StoredEventView view = StoredEventView.of(event, attrs);
                String group = ruleMatcher.matchGroup(rule, view);
                if (group != null && group.equals(aggregate.getGroupKey())) {
                    expected.add(event.getEventId());
                    contributions.add(new WindowContribution(
                            event.getEventId(), event.getEventTime(), event.getIngestTime(),
                            event.getActor(), event.getAction(), event.getTarget(), event.getSourceIp()));
                }
            }
        }
        contributions.sort(Comparator.comparing(WindowContribution::eventTime)
                .thenComparing(WindowContribution::eventId));

        // 3.3 差异（明细，不只是总数）
        Set<String> missing = new TreeSet<>(expected);
        missing.removeAll(linked);
        Set<String> unexpected = new TreeSet<>(linked);
        unexpected.removeAll(expected);

        long storedCount = aggregate.getCount();
        long uniqueCount = expected.size();
        long diff = storedCount - uniqueCount;
        boolean countConsistent = storedCount == uniqueCount
                && missing.isEmpty() && unexpected.isEmpty();
        boolean shouldFire = uniqueCount >= threshold;
        boolean firingConsistent = aggregate.isFired() == shouldFire
                && (!shouldFire || aggregate.getMatchedAlertId() != null);
        boolean consistent = countConsistent && firingConsistent;

        // 3.4 关联告警
        AlertEntity matched = aggregate.getMatchedAlertId() == null ? null
                : alertRepository.findById(aggregate.getMatchedAlertId()).orElse(null);
        List<AlertEntity> carrying = alertRepository.findByWindowKey(windowKey);
        // 优先展示 aggregate.matchedAlertId 指向的告警；若该告警已不存在，则展示实际携带窗口键者
        AlertEntity alert = matched != null ? matched : carrying.stream().findFirst().orElse(null);
        AlertBrief alertBrief = alert == null ? null : new AlertBrief(
                alert.getId(), alert.getStatus(), alert.getOccurrenceCount(),
                alert.getWindowKeys().size());

        return new WindowReconciliationResult(
                windowKey,
                aggregate.getRuleId(),
                ruleCode,
                aggregate.getVersion(),
                aggregate.getGroupKey(),
                Instant.ofEpochSecond(windowStart),
                Instant.ofEpochSecond(windowEnd),
                threshold,
                storedCount,
                uniqueCount,
                diff,
                aggregate.isFired(),
                shouldFire,
                countConsistent,
                firingConsistent,
                consistent,
                aggregate.getMatchedAlertId(),
                alertBrief,
                List.copyOf(missing),
                List.copyOf(unexpected),
                List.copyOf(contributions)
        );
    }

    private void validateQuery(ReconciliationQuery query) {
        if (query.ruleCode() != null && query.version() != null) {
            ruleRepository.findByRuleCodeAndVersion(query.ruleCode(), query.version())
                    .orElseThrow(() -> new PipelineException(RULE_NOT_FOUND,
                            "规则版本不存在: " + query.ruleCode() + "#v" + query.version()));
        } else if (query.ruleCode() != null
                && ruleRepository.findByRuleCodeOrderByVersionDesc(query.ruleCode()).isEmpty()) {
            throw new PipelineException(RULE_NOT_FOUND, "规则不存在: " + query.ruleCode());
        }
        if (query.windowStartFrom() != null && query.windowStartTo() != null
                && query.windowStartFrom() > query.windowStartTo()) {
            throw new PipelineException(RejectReason.ILLEGAL_FORMAT,
                    "窗口区间非法: from 不能大于 to");
        }
    }

    private String ruleCodeOf(long ruleId) {
        return ruleRepository.findById(ruleId).map(RuleEntity::getRuleCode).orElse("__UNKNOWN__");
    }

    static String encodeWindowKey(WindowAggregateEntity a) {
        return a.getRuleId() + "#v" + a.getVersion() + "#" + a.getGroupKey() + "#" + a.getWindowStart();
    }

    /**
     * 事件受理时刻该规则版本是否在生效：不早于版本创建时刻；
     * 且若版本已被取代（supersededAt 非空），受理时刻不得晚于取代时刻。
     */
    static boolean acceptedWhileVersionActive(RuleEntity rule, EventEntity event) {
        Instant ingest = event.getIngestTime();
        if (ingest == null || ingest.isBefore(rule.getCreatedAt())) {
            return false;
        }
        return rule.getSupersededAt() == null || !ingest.isAfter(rule.getSupersededAt());
    }
}
