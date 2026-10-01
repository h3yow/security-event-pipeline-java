package com.github.h3yow.securityeventpipelinejava.domain;

import com.github.h3yow.securityeventpipelinejava.common.EventSource;

import java.time.Instant;
import java.util.Map;

/**
 * 归一化后的安全事件（事件时间 eventTime 是窗口判定的唯一时间基准）。
 */
public record NormalizedEvent(
        String eventId,
        EventSource source,
        Instant eventTime,
        Instant ingestTime,
        String actor,
        String action,
        String target,
        String sourceIp,
        Map<String, String> attributes,
        String rawPayload
) {
    /** 返回一个接入时间被替换为指定值的副本（其余字段不变）。 */
    public NormalizedEvent withIngestTime(Instant newIngestTime) {
        return new NormalizedEvent(eventId, source, eventTime, newIngestTime,
                actor, action, target, sourceIp, attributes, rawPayload);
    }
}
