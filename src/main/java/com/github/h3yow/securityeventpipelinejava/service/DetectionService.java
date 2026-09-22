package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.domain.RuleMatch;
import com.github.h3yow.securityeventpipelinejava.domain.WindowKey;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.exception.ValidationException;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

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
 *   <li>JVM 内按窗口键加锁串行化同窗口更新；</li>
 *   <li>window_event(rule_id,window_key,event_id) 唯一约束 + 先查后插保证每个事件对每个窗口只计一次，
 *       计数不重复不遗漏；</li>
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

    private final Map<String, Lock> windowLocks = new ConcurrentHashMap<>();

    public DetectionService(RuleService ruleService,
                            EventRepository eventRepository,
                            RuleRepository ruleRepository,
                            WindowAggregateRepository aggregateRepository,
                            WindowEventRepository windowEventRepository,
                            AlertService alertService,
                            JsonService jsonService) {
        this.ruleService = ruleService;
        this.eventRepository = eventRepository;
        this.ruleRepository = ruleRepository;
        this.aggregateRepository = aggregateRepository;
        this.windowEventRepository = windowEventRepository;
        this.alertService = alertService;
        this.jsonService = jsonService;
    }

    /**
     * 单一事务内完成：事件落库 + 全部规则的窗口计数/建警。
     * 任一步骤抛出运行时异常都会整体回滚（重复事件由接入层先判 + 唯一约束兜底）。
     */
    @Transactional
    public List<Long> processEvent(NormalizedEvent event) {
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
            throw new com.github.h3yow.securityeventpipelinejava.exception.DuplicateEventException(
                    event.eventId());
        }
        return evaluate(event);
    }

    @Transactional
    public List<Long> evaluate(NormalizedEvent event) {
        List<Long> alertIds = new ArrayList<>();
        for (RuleEntity rule : ruleService.activeRules()) {
            RuleMatch match = match(rule, event);
            if (match == null) {
                continue;
            }
            long windowStart = floorToWindow(event.eventTime(), rule.getWindowSeconds());
            long windowEnd = windowStart + rule.getWindowSeconds();
            WindowKey key = new WindowKey(rule.getId(), rule.getVersion(), match.groupKey(), windowStart);

            Instant now = Instant.now();
            if (now.getEpochSecond() > windowEnd + rule.getAllowedLatenessSeconds()) {
                log.warn("迟到事件窗口已关闭被拒绝: eventId={}, rule={}#v{}, window={}, now={}, 允许迟到={}s",
                        event.eventId(), rule.getRuleCode(), rule.getVersion(), key.encode(),
                        now, rule.getAllowedLatenessSeconds());
                throw new ValidationException(RejectReason.WINDOW_EXPIRED, String.format(
                        "事件 %s 属于窗口 [%s, %s)，该窗口已超过规则 %s 允许的 %d 秒迟到宽限，判定不再接受",
                        event.eventId(), Instant.ofEpochSecond(windowStart), Instant.ofEpochSecond(windowEnd),
                        rule.getRuleCode(), rule.getAllowedLatenessSeconds()));
            }

            Long alertId = accumulateWindow(rule, key, windowEnd, event);
            if (alertId != null && !alertIds.contains(alertId)) {
                alertIds.add(alertId);
            }
        }
        return alertIds;
    }

    private Long accumulateWindow(RuleEntity rule, WindowKey key, long windowEnd,
                                  NormalizedEvent event) {
        Lock lock = windowLocks.computeIfAbsent(key.encode(), k -> new ReentrantLock());
        lock.lock();
        try {
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
                // 唯一约束兜底：并发下第二个插入失败 => 不计数
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
        } finally {
            lock.unlock();
        }
    }

    /** 归一化事件是否匹配规则；匹配则返回 RuleMatch(含分组值)，否则 null。 */
    private RuleMatch match(RuleEntity rule, NormalizedEvent event) {
        Map<String, String> conditions = jsonService.readStringMap(rule.getMatchConditionsJson());
        for (Map.Entry<String, String> c : conditions.entrySet()) {
            String actual = extractField(event, c.getKey());
            if (actual == null || !actual.equals(c.getValue())) {
                return null;
            }
        }
        String groupKey = "__GLOBAL__".equals(rule.getGroupBy())
                ? "__GLOBAL__"
                : extractField(event, rule.getGroupBy());
        if (groupKey == null) {
            // 分组字段缺失无法关联，按不匹配处理（归一化阶段已保证必填字段存在）
            return null;
        }
        return new RuleMatch(rule.getId(), rule.getVersion(), groupKey);
    }

    private String extractField(NormalizedEvent event, String field) {
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

    private long floorToWindow(Instant t, long windowSeconds) {
        long epoch = t.getEpochSecond();
        return Math.floorDiv(epoch, windowSeconds) * windowSeconds;
    }
}
