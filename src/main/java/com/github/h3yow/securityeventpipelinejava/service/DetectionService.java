package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.domain.RuleMatch;
import com.github.h3yow.securityeventpipelinejava.domain.WindowKey;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.exception.DuplicateEventException;
import com.github.h3yow.securityeventpipelinejava.exception.ValidationException;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * 基于时间窗口的关联检测引擎。
 *
 * <h3>窗口语义</h3>
 * <ul>
 *   <li>滚动(tumbling)窗口，按<b>事件时间</b>对齐：windowStart = floor(eventTime / windowSeconds)；
 *       因此事件乱序或迟到，只要落入同一时间桶，判定结论完全一致、与到达顺序无关。</li>
 *   <li>迟到判定基于<b>接入时刻墙上时钟</b>：now &gt; windowEnd + allowedLatenessSeconds 即拒绝(WINDOW_EXPIRED)。
 *       该判定与处理顺序无关、重启后依旧成立，保证结论稳定可解释。</li>
 *   <li>时钟偏移：事件时间超出全局容忍范围在归一化阶段拒绝(TIMESTAMP_OUT_OF_RANGE)。</li>
 * </ul>
 *
 * <h3>并发正确性</h3>
 * <ul>
 *   <li>JVM 内按窗口键加锁，且<b>锁覆盖整个事务直到提交</b>（见 {@link WindowLockManager}），
 *       同一窗口的不同事件并发补录时，"读聚合→写关联→改计数"完全串行化，
 *       不会出现聚合行唯一约束冲突或计数丢失更新；</li>
 *   <li>一个事件命中多个规则时按窗口键字典序统一加锁，固定加锁顺序避免死锁；</li>
 *   <li>window_event(rule_id,window_key,event_id) 唯一约束作为兜底，每个事件对每个窗口只计一次；</li>
 *   <li>所有计数与告警落库，重启后可继续累计（不会回退或重复累计）。</li>
 * </ul>
 */
@Service
public class DetectionService {

    private static final Logger log = LoggerFactory.getLogger(DetectionService.class);

    private final RuleService ruleService;
    private final EventRepository eventRepository;
    private final RuleRepository ruleRepository;
    private final WindowAggregateRepository aggregateRepository;
    private final WindowEventRepository windowEventRepository;
    private final AlertService alertService;
    private final JsonService jsonService;
    private final WindowLockManager windowLockManager;
    private final TransactionTemplate transactionTemplate;

    public DetectionService(RuleService ruleService,
                            EventRepository eventRepository,
                            RuleRepository ruleRepository,
                            WindowAggregateRepository aggregateRepository,
                            WindowEventRepository windowEventRepository,
                            AlertService alertService,
                            JsonService jsonService,
                            WindowLockManager windowLockManager,
                            PlatformTransactionManager transactionManager) {
        this.ruleService = ruleService;
        this.eventRepository = eventRepository;
        this.ruleRepository = ruleRepository;
        this.aggregateRepository = aggregateRepository;
        this.windowEventRepository = windowEventRepository;
        this.alertService = alertService;
        this.jsonService = jsonService;
        this.windowLockManager = windowLockManager;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    /** 待处理的一次规则命中：规则 + 所属窗口键。 */
    private record PendingWindow(RuleEntity rule, WindowKey key, long windowEnd) {
    }

    /**
     * 事件落库 + 全部命中规则的窗口计数/建警，原子完成。
     *
     * <p><b>先取全部活跃规则的 ruleCode 锁、再在锁内做匹配/迟到判定，最后取窗口锁</b>
     * （固定"规则锁→窗口锁"顺序避免死锁）：版本选择与迟到宽限都以锁内的受理时刻
     * （decisionTime）为准，与同 ruleCode 的规则升级互斥，杜绝"锁外按旧版本预检、
     * 锁内已升级"的边界误判。事件 ingestTime 取 decisionTime 落库，
     * 对账按 {@code [createdAt(v), createdAt(v+1))} 重算必然得到同一结论。
     */
    public List<Long> processEvent(NormalizedEvent event) {
        // 规则编码集合在锁外读取仅用于决定要取哪些 ruleCode 锁；锁内会重新读取版本
        List<String> ruleCodes = ruleService.activeRules().stream()
                .map(RuleEntity::getRuleCode).distinct().sorted().toList();

        return windowLockManager.callLocked(ruleCodes, List.of(), () -> {
            // 锁内的受理时刻：与升级创建新版本的时刻在 ruleCode 锁上线性化
            Instant decisionTime = Instant.now();
            List<RuleEntity> rulesAtIngest = effectiveRulesAt(decisionTime);
            // 匹配 + 迟到判定都在规则锁内完成（可能抛 WINDOW_EXPIRED，此时尚未写库）
            List<PendingWindow> pending = matchWindows(event, decisionTime, rulesAtIngest);

            if (pending.isEmpty()) {
                // 未命中任何规则：事件照常受理落库，只是不产生窗口计数/告警
                List<Long> empty = new ArrayList<>();
                transactionTemplate.executeWithoutResult(status ->
                        insertAcceptedEvent(event.withIngestTime(decisionTime)));
                return empty;
            }

            List<String> windowKeys = pending.stream()
                    .map(p -> p.key().encode()).sorted().distinct().toList();
            List<Long> alertIds = new ArrayList<>();
            windowLockManager.runLocked(windowKeys, () ->
                    transactionTemplate.executeWithoutResult(status -> {
                        insertAcceptedEvent(event.withIngestTime(decisionTime));
                        for (PendingWindow p : pending) {
                            Long alertId = accumulateWindow(p.rule(), p.key(), p.windowEnd(), event);
                            if (alertId != null && !alertIds.contains(alertId)) {
                                alertIds.add(alertId);
                            }
                        }
                    }));
            return alertIds;
        });
    }

    /**
     * 给定时刻每个 ruleCode 生效的规则版本：版本历史中 {@code createdAt <= at} 的最新版本
     * （且仍 enabled）。与对账重算的版本归属口径一致：
     * v 版本生效区间为 {@code [createdAt(v), createdAt(v+1))}。
     */
    private List<RuleEntity> effectiveRulesAt(Instant at) {
        return ruleRepository.findAll().stream()
                .filter(RuleEntity::isEnabled)
                .collect(java.util.stream.Collectors.groupingBy(RuleEntity::getRuleCode))
                .values().stream()
                .map(versions -> versions.stream()
                        .filter(r -> !r.getCreatedAt().isAfter(at))
                        .max(Comparator.comparingInt(RuleEntity::getVersion))
                        .orElse(null))
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    /** 计算事件在给定规则集合下命中的全部窗口，并完成迟到判定（写库前校验）。 */
    private List<PendingWindow> matchWindows(NormalizedEvent event, Instant now,
                                             List<RuleEntity> rules) {
        List<PendingWindow> pending = new ArrayList<>();
        for (RuleEntity rule : rules) {
            RuleMatch match = match(rule, event);
            if (match == null) {
                continue;
            }
            long windowStart = floorToWindow(event.eventTime(), rule.getWindowSeconds());
            long windowEnd = windowStart + rule.getWindowSeconds();
            WindowKey key = new WindowKey(rule.getId(), rule.getVersion(), match.groupKey(), windowStart);

            if (now.getEpochSecond() > windowEnd + rule.getAllowedLatenessSeconds()) {
                log.warn("迟到事件窗口已关闭被拒绝: eventId={}, rule={}#v{}, window={}, now={}, 允许迟到={}s",
                        event.eventId(), rule.getRuleCode(), rule.getVersion(), key.encode(),
                        now, rule.getAllowedLatenessSeconds());
                throw new ValidationException(RejectReason.WINDOW_EXPIRED, String.format(
                        "事件 %s 属于窗口 [%s, %s)，该窗口已超过规则 %s 允许的 %d 秒迟到宽限，判定不再接受",
                        event.eventId(), Instant.ofEpochSecond(windowStart), Instant.ofEpochSecond(windowEnd),
                        rule.getRuleCode(), rule.getAllowedLatenessSeconds()));
            }
            pending.add(new PendingWindow(rule, key, windowEnd));
        }
        return pending;
    }

    private void insertAcceptedEvent(NormalizedEvent event) {
        EventEntity entity = new EventEntity();
        entity.setEventId(event.eventId());
        entity.setSource(event.source().name());
        entity.setEventTime(event.eventTime());
        entity.setIngestTime(event.ingestTime());
        entity.setActor(event.actor());
        entity.setAction(event.action());
        entity.setTarget(event.target());
        entity.setSourceIp(event.sourceIp());
        entity.setAttributesJson(jsonService.write(event.attributes()));
        entity.setRawPayload(event.rawPayload());
        try {
            eventRepository.saveAndFlush(entity);
        } catch (DataIntegrityViolationException dup) {
            // 极端并发下由唯一约束兜底：同一事件只会被接受一次
            log.warn("event_id 唯一约束判定重复: eventId={}", event.eventId());
            throw new DuplicateEventException(event.eventId());
        }
    }

    /**
     * 在"窗口锁 + 事务"保护下累加一个窗口。调用方必须已持有该窗口锁且处于事务中。
     */
    private Long accumulateWindow(RuleEntity rule, WindowKey key, long windowEnd,
                                  NormalizedEvent event) {
        boolean duplicateInWindow = windowEventRepository
                .existsByRuleIdAndWindowKeyAndEventId(rule.getId(), key.encode(), event.eventId());
        if (duplicateInWindow) {
            log.info("事件已在窗口内计过数，跳过(幂等): eventId={}, window={}",
                    event.eventId(), key.encode());
            return aggregateRepository
                    .findByRuleIdAndVersionAndGroupKeyAndWindowStart(
                            rule.getId(), key.version(), key.groupKey(), key.windowStart())
                    .map(WindowAggregateEntity::getMatchedAlertId).orElse(null);
        }

        WindowAggregateEntity aggregate = aggregateRepository
                .findByRuleIdAndVersionAndGroupKeyAndWindowStart(
                        rule.getId(), key.version(), key.groupKey(), key.windowStart())
                .orElseGet(() -> {
                    WindowAggregateEntity a = new WindowAggregateEntity();
                    a.setRuleId(rule.getId());
                    a.setVersion(rule.getVersion());
                    a.setGroupKey(key.groupKey());
                    a.setWindowStart(key.windowStart());
                    a.setWindowEnd(windowEnd);
                    a.setCount(0);
                    a.setThreshold(rule.getThreshold());
                    a.setFired(false);
                    return a;
                });

        try {
            // 唯一约束兜底：即使锁外有极端并发，第二个插入失败 => 不计数
            windowEventRepository.saveAndFlush(new WindowEventEntity(
                    rule.getId(), key.encode(), event.eventId()));
        } catch (DataIntegrityViolationException dup) {
            log.info("窗口关联唯一约束判定重复，跳过计数: eventId={}, window={}",
                    event.eventId(), key.encode());
            return aggregate.getMatchedAlertId();
        }

        aggregate.setCount(aggregate.getCount() + 1);
        boolean reaches = aggregate.getCount() >= rule.getThreshold();
        log.info("窗口计数: eventId={}, rule={}#v{}, group={}, window=[{},{}), count={}, threshold={}, 命中={}",
                event.eventId(), rule.getRuleCode(), rule.getVersion(), key.groupKey(),
                Instant.ofEpochSecond(key.windowStart()), Instant.ofEpochSecond(windowEnd),
                aggregate.getCount(), rule.getThreshold(), reaches);

        Long alertId = aggregate.getMatchedAlertId();
        if (reaches) {
            if (alertId == null) {
                alertId = alertService.fireOrMerge(
                        ruleRepository.findById(rule.getId()).orElse(rule), key, event, aggregate);
            } else {
                // 已建警窗口的后续事件：计数继续，但不重复建警（窗口内只触发一次）
                log.info("窗口已触发过告警，后续事件仅累计: window={}, alertId={}", key.encode(), alertId);
            }
            aggregate.setFired(true);
        }
        aggregateRepository.save(aggregate);
        return alertId;
    }

    /** 归一化事件是否匹配规则；匹配则返回 RuleMatch(含分组值)，否则 null。 */
    private RuleMatch match(RuleEntity rule, NormalizedEvent event) {
        return WindowRuleMatcher.match(rule, event, jsonService);
    }

    static long floorToWindow(Instant t, long windowSeconds) {
        long epoch = t.getEpochSecond();
        return Math.floorDiv(epoch, windowSeconds) * windowSeconds;
    }

    /** 归一化事件字段取值（规则匹配复用）。 */
    public static String extractField(NormalizedEvent event, String field) {
        return switch (field) {
            case "eventId" -> event.eventId();
            case "source" -> event.source().name();
            case "actor" -> event.actor();
            case "action" -> event.action();
            case "target" -> event.target();
            case "sourceIp" -> event.sourceIp();
            default -> event.attributes().get(field);
        };
    }
}
