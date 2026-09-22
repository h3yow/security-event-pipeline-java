package com.github.h3yow.securityeventpipelinejava.detection;

import com.github.h3yow.securityeventpipelinejava.model.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.persistence.DetectionRuleRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.NormalizedEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 基于事件时间的滑动窗口关联检测。
 *
 * 语义：对新到事件 e，对每条匹配动作的规则，评估所有"锚点窗口"——
 * 即以同分组内事件时间落在 [e.eventTime, e.eventTime + window] 的每个事件
 * 为窗口右端点的窗口。这样乱序/迟到事件不仅评估自己的窗口，
 * 还会补评它参与计数的更晚锚点窗口，使最终结论与到达顺序无关。
 * 计数由已持久化的唯一事件（eventId 去重）实时重算，
 * 因此乱序、并发提交不会重复计数，重启后状态不丢失。
 */
@Service
public class RuleEngine {

    private static final Logger log = LoggerFactory.getLogger(RuleEngine.class);

    private final DetectionRuleRepository ruleRepository;
    private final NormalizedEventRepository eventRepository;

    public RuleEngine(DetectionRuleRepository ruleRepository,
                      NormalizedEventRepository eventRepository) {
        this.ruleRepository = ruleRepository;
        this.eventRepository = eventRepository;
    }

    /**
     * 针对新到事件评估所有启用规则。
     *
     * @param event 已持久化的归一化事件
     * @return 每条匹配规则的评估结果（含判定依据）
     */
    public List<WindowEvaluation> evaluate(NormalizedEvent event) {
        List<WindowEvaluation> results = new ArrayList<>();
        for (DetectionRule rule : ruleRepository.findLatestEnabledRules()) {
            if (!rule.getAction().equals(event.getAction())) {
                continue;
            }
            // 锚点：同分组内事件时间 >= 新事件且 <= 新事件+window 的所有事件（含新事件自身）。
            // 新事件可能补齐这些更晚锚点的窗口，乱序到达也能得到与正序一致的结论。
            List<NormalizedEvent> anchors = eventRepository.findWindowEvents(
                    event.getGroupKey(), rule.getAction(),
                    event.getEventTime(), event.getEventTime().plusSeconds(rule.getWindowSeconds()));
            for (NormalizedEvent anchor : anchors) {
                Instant windowEnd = anchor.getEventTime();
                Instant windowStart = windowEnd.minusSeconds(rule.getWindowSeconds());
                List<NormalizedEvent> windowEvents = eventRepository.findWindowEvents(
                        event.getGroupKey(), rule.getAction(), windowStart, windowEnd);
                List<String> eventIds = windowEvents.stream()
                        .map(NormalizedEvent::getEventId).toList();
                boolean triggered = eventIds.size() >= rule.getThreshold();
                WindowEvaluation eval = new WindowEvaluation(rule.getRuleId(), rule.getVersion(),
                        event.getGroupKey(), windowStart, windowEnd,
                        eventIds.size(), rule.getThreshold(), triggered, eventIds);
                log.info("window evaluation: rule={}@v{} group={} anchor={} window=[{}, {}] count={} threshold={} triggered={} eventIds={}",
                        eval.ruleId(), eval.ruleVersion(), eval.groupKey(), anchor.getEventId(),
                        eval.windowStart(), eval.windowEnd(), eval.count(), eval.threshold(),
                        eval.triggered(), eval.eventIds());
                results.add(eval);
            }
        }
        return results;
    }
}
