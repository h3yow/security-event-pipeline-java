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
}
