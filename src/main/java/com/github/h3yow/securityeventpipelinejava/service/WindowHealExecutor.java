package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.domain.StoredEventView;
import com.github.h3yow.securityeventpipelinejava.domain.WindowKey;
import com.github.h3yow.securityeventpipelinejava.domain.healing.WindowHealChange;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * 单窗口自愈事务执行器（独立 Bean 以保证 {@link Transactional} 经代理生效）。
 *
 * <p>调用方（{@link HealingService}）必须已持有该窗口的 JVM 锁；本执行器在<b>独立短事务</b>内：
 * <ol>
 *   <li>按规则版本快照对全部已受理事件复算，得到应纳入窗口的去重事件集合；</li>
 *   <li>把缺失的 window_event 关联补上、多余的摘除，使关联表成为权威真相；</li>
 *   <li>把 aggregate 的 count/fired/matchedAlertId 收敛到正确值；</li>
 *   <li>委托 {@link AlertService#reconcileForHealing} 收敛告警（不重复建警、不误报）。</li>
 * </ol>
 * 本方法天然幂等：窗口已正确时所有集合差为空、不写任何数据，返回 changed=false。
 */
@Service
public class WindowHealExecutor {

    private static final Logger log = LoggerFactory.getLogger(WindowHealExecutor.class);

    private final WindowAggregateRepository aggregateRepository;
    private final WindowEventRepository windowEventRepository;
    private final EventRepository eventRepository;
    private final RuleMatcher ruleMatcher;
    private final AlertService alertService;
    private final JsonService jsonService;

    public WindowHealExecutor(WindowAggregateRepository aggregateRepository,
                              WindowEventRepository windowEventRepository,
                              EventRepository eventRepository,
                              RuleMatcher ruleMatcher,
                              AlertService alertService,
                              JsonService jsonService) {
        this.aggregateRepository = aggregateRepository;
        this.windowEventRepository = windowEventRepository;
        this.eventRepository = eventRepository;
        this.ruleMatcher = ruleMatcher;
        this.alertService = alertService;
        this.jsonService = jsonService;
    }

    @Transactional
    public WindowHealChange healWindow(WindowAggregateEntity aggregate, RuleEntity rule) {
        String windowKey = encodeWindowKey(aggregate);
        long windowStart = aggregate.getWindowStart();
        long windowEnd = aggregate.getWindowEnd();

        List<WindowEventEntity> links = windowEventRepository.findByWindowKeyOrderByEventIdAsc(windowKey);
        Set<String> linked = new TreeSet<>();
        for (WindowEventEntity l : links) {
            linked.add(l.getEventId());
        }

        // 1. 复算应纳入的去重事件（已受理 ∩ 受理时该版本生效 ∩ 事件时间在窗口内 ∩ 匹配且同组）
        Set<String> expected = new TreeSet<>();
        if (rule != null) {
            for (EventEntity event : eventRepository.findAll()) {
                long t = event.getEventTime().getEpochSecond();
                if (t < windowStart || t >= windowEnd) {
                    continue;
                }
                if (!ReconciliationService.acceptedWhileVersionActive(rule, event)) {
                    continue;
                }
                Map<String, String> attrs = jsonService.readStringMap(event.getAttributesJson());
                StoredEventView view = StoredEventView.of(event, attrs);
                String group = ruleMatcher.matchGroup(rule, view);
                if (group != null && group.equals(aggregate.getGroupKey())) {
                    expected.add(event.getEventId());
                }
            }
        }

        Set<String> toAdd = new TreeSet<>(expected);
        toAdd.removeAll(linked);
        Set<String> toRemove = new TreeSet<>(linked);
        toRemove.removeAll(expected);

        long beforeCount = aggregate.getCount();
        boolean beforeFired = aggregate.isFired();
        Long beforeAlertId = aggregate.getMatchedAlertId();

        // 2. 关联表收敛：补缺失（全部是已受理事件）、摘多余
        for (String eventId : toAdd) {
            windowEventRepository.save(new WindowEventEntity(aggregate.getRuleId(), windowKey, eventId));
            log.info("自愈: 窗口 {} 补录缺失关联 eventId={}", windowKey, eventId);
        }
        if (!toRemove.isEmpty()) {
            windowEventRepository.deleteByWindowKeyAndEventIdIn(windowKey, new ArrayList<>(toRemove));
            log.info("自愈: 窗口 {} 摘除多余关联 eventIds={}", windowKey, toRemove);
        }

        // 3. 聚合计数/触发标志收敛
        long afterCount = expected.size();
        boolean shouldFire = rule != null && afterCount >= aggregate.getThreshold();
        aggregate.setCount(afterCount);

        Long alertId = beforeAlertId;
        String alertAction = "NONE";
        if (rule != null) {
            WindowKey key = new WindowKey(aggregate.getRuleId(), aggregate.getVersion(),
                    aggregate.getGroupKey(), aggregate.getWindowStart());
            var result = alertService.reconcileForHealing(rule, key, afterCount);
            alertAction = result.action();
            alertId = shouldFire ? result.alertId() : null;
        }
        aggregate.setFired(shouldFire);
        aggregate.setMatchedAlertId(alertId);
        aggregateRepository.save(aggregate);

        boolean changed = !toAdd.isEmpty() || !toRemove.isEmpty()
                || beforeCount != afterCount || beforeFired != shouldFire
                || !java.util.Objects.equals(beforeAlertId, alertId);

        return new WindowHealChange(
                windowKey, List.copyOf(linked), List.copyOf(expected),
                List.copyOf(toAdd), List.copyOf(toRemove),
                beforeCount, afterCount, beforeFired, shouldFire,
                alertId, alertAction, changed);
    }

    private static String encodeWindowKey(WindowAggregateEntity a) {
        return a.getRuleId() + "#v" + a.getVersion() + "#" + a.getGroupKey() + "#" + a.getWindowStart();
    }
}
