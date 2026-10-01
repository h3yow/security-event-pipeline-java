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
    /**
     * 返回受理时刻被替换为 ingestTime 的副本。归一化时刻只代表请求解析完成，
     * 真正的受理时刻在规则部署读视图内确定，用于把事件归属到受理时生效的规则版本。
     */
    public NormalizedEvent withIngestTime(Instant ingestTime) {
        return new NormalizedEvent(eventId, source, eventTime, ingestTime,
                actor, action, target, sourceIp, attributes, rawPayload);
    }
}
