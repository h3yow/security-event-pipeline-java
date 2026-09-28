package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.domain.WindowKey;
import com.github.h3yow.securityeventpipelinejava.domain.WindowTarget;
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
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

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
 * 同一窗口的读-改-写由 {@link WindowLockManager} 的 JVM 锁在<b>事务外</b>串行化
 * （调用方负责按窗口键排序加锁，避免死锁）；事务内部不再依赖锁内判断，
 * {@code window_event} 唯一约束仍作为多实例/极端竞态的数据库兜底。
 * 因此同一窗口里几十条<b>不同</b>事件并发提交时，每条都能成功受理并恰好计一次数；
 * 相同事件重试只计一次。
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
    private final RuleMatcher ruleMatcher;

    public DetectionService(RuleService ruleService,
                            EventRepository eventRepository,
                            RuleRepository ruleRepository,
                            WindowAggregateRepository aggregateRepository,
                            WindowEventRepository windowEventRepository,
                            AlertService alertService,
                            JsonService jsonService,
                            RuleMatcher ruleMatcher) {
        this.ruleService = ruleService;
        this.eventRepository = eventRepository;
        this.ruleRepository = ruleRepository;
        this.aggregateRepository = aggregateRepository;
        this.windowEventRepository = windowEventRepository;
        this.alertService = alertService;
        this.jsonService = jsonService;
        this.ruleMatcher = ruleMatcher;
    }

    /**
     * 计算事件对所有当前生效规则的判定目标（非事务、纯计算）。
     * 若事件属于已超过迟到宽限的窗口，直接抛 {@link ValidationException}(WINDOW_EXPIRED)。
     */
    public List<WindowTarget> resolveTargets(NormalizedEvent event) {
        List<WindowTarget> targets = new ArrayList<>();
        for (RuleEntity rule : ruleService.activeRules()) {
            String groupKey = ruleMatcher.matchGroup(rule, event.asView());
            if (groupKey == null) {
                continue;
            }
            long windowStart = floorToWindow(event.eventTime(), rule.getWindowSeconds());
            long windowEnd = windowStart + rule.getWindowSeconds();
            WindowKey key = new WindowKey(rule.getId(), rule.getVersion(), groupKey, windowStart);

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
            targets.add(new WindowTarget(rule, key, windowEnd));
        }
        // 按窗口键排序：调用方据此以全局一致顺序加锁，杜绝多窗口交叉加锁导致的死锁
        targets.sort(Comparator.comparing(t -> t.key().encode()));
        return targets;
    }

    /**
     * 单一事务内完成：事件落库 + 全部命中窗口的计数/建警。
     * <b>调用方必须已按 {@code targets} 的顺序持有全部窗口锁。</b>
     * 任一步骤抛运行时异常都会整体回滚（重复事件由接入层先判 + 唯一约束兜底）。
     */
    @Transactional
    public List<Long> processEvent(NormalizedEvent event, List<WindowTarget> targets) {
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

        List<Long> alertIds = new ArrayList<>();
        for (WindowTarget target : targets) {
            Long alertId = accumulateWindow(target.rule(), target.key(), target.windowEnd(), event);
            if (alertId != null && !alertIds.contains(alertId)) {
                alertIds.add(alertId);
            }
        }
        return alertIds;
    }

    /**
     * 窗口读-改-写（调用方已持窗口锁、当前处于事务内）。
     * 窗口关联表先查后插 + 唯一约束兜底：每个事件对每个窗口恰好贡献一次。
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
            // 唯一约束兜底：多实例/极端竞态下并发插入，第二个失败 => 不计数
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

    private long floorToWindow(Instant t, long windowSeconds) {
        long epoch = t.getEpochSecond();
        return Math.floorDiv(epoch, windowSeconds) * windowSeconds;
    }
}
