package com.github.h3yow.securityeventpipelinejava.domain;

import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;

import java.time.Instant;
import java.util.Map;

/**
 * 已落库历史事件的 {@link EventView} 适配，供对账/自愈按规则版本快照复算匹配。
 */
public record StoredEventView(
        String eventId,
        String source,
        Instant eventTime,
        String actor,
        String action,
        String target,
        String sourceIp,
        Map<String, String> attributes
) implements EventView {

    public static StoredEventView of(EventEntity e, Map<String, String> attributes) {
        return new StoredEventView(
                e.getEventId(), e.getSource(), e.getEventTime(),
                e.getActor(), e.getAction(), e.getTarget(), e.getSourceIp(),
                attributes == null ? Map.of() : attributes);
    }
}
