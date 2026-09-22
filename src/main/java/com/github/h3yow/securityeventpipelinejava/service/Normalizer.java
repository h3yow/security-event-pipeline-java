package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.common.EventSource;
import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.exception.ValidationException;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;

import static com.github.h3yow.securityeventpipelinejava.common.RejectReason.ILLEGAL_FORMAT;
import static com.github.h3yow.securityeventpipelinejava.common.RejectReason.MISSING_FIELD;
import static com.github.h3yow.securityeventpipelinejava.common.RejectReason.TIMESTAMP_OUT_OF_RANGE;

/**
 * 多来源原始日志归一化。
 *
 * <p>两种来源的必填字段：
 * <ul>
 *   <li>FIREWALL: eventId, timestamp(ISO-8601), srcIp, action, target</li>
 *   <li>AUTH: eventId, timestamp(ISO-8601), username, result, service</li>
 * </ul>
 * 时间戳统一解析为 {@link Instant}，时区偏移按 ISO 文本自带偏移处理；无法解析为 INVALID_TIMESTAMP，
 * 超出时钟容忍范围为 TIMESTAMP_OUT_OF_RANGE，字段缺失/空白为 MISSING_FIELD，类型错误为 ILLEGAL_FORMAT。
 */
@Component
public class Normalizer {

    private static final Logger log = LoggerFactory.getLogger(Normalizer.class);

    private final long maxClockSkewSeconds;
    private final long maxFutureSeconds;

    public Normalizer(org.springframework.core.env.Environment env) {
        this.maxClockSkewSeconds = Long.parseLong(
                env.getProperty("pipeline.max-clock-skew-seconds", "86400"));
        this.maxFutureSeconds = Long.parseLong(
                env.getProperty("pipeline.max-future-seconds", "300"));
    }

    public NormalizedEvent normalize(EventIngestRequest request, String rawJson) {
        if (request == null || request.source() == null || request.source().isBlank()) {
            throw reject(MISSING_FIELD, "缺少 source 字段", rawJson);
        }
        EventSource source;
        try {
            source = EventSource.valueOf(request.source().trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw reject(RejectReason.UNKNOWN_SOURCE,
                    "不支持的日志来源: " + request.source(), rawJson);
        }
        Map<String, Object> payload = request.payload();
        if (payload == null || payload.isEmpty()) {
            throw reject(MISSING_FIELD, "缺少 payload", rawJson);
        }

        String eventId = requireString(payload, "eventId", rawJson);
        Instant eventTime = parseTimestamp(required(payload, "timestamp", rawJson), rawJson);
        validateClockRange(eventId, eventTime, rawJson);

        NormalizedEvent event;
        if (source == EventSource.FIREWALL) {
            String srcIp = requireString(payload, "srcIp", rawJson);
            String action = requireString(payload, "action", rawJson);
            String target = requireString(payload, "target", rawJson);
            Map<String, String> attrs = new HashMap<>();
            putIfPresent(attrs, "zone", payload, rawJson);
            putIfPresent(attrs, "bytes", payload, rawJson);
            event = new NormalizedEvent(eventId, source, eventTime, Instant.now(),
                    null, action, target, srcIp, attrs, rawJson);
        } else {
            String username = requireString(payload, "username", rawJson);
            String result = requireString(payload, "result", rawJson);
            String service = requireString(payload, "service", rawJson);
            Map<String, String> attrs = new HashMap<>();
            putIfPresent(attrs, "srcIp", payload, rawJson);
            event = new NormalizedEvent(eventId, source, eventTime, Instant.now(),
                    username, result, service,
                    asStringOrNull(payload.get("srcIp")), attrs, rawJson);
        }
        log.info("归一化成功: eventId={}, source={}, eventTime={}, actor={}, action={}, target={}",
                event.eventId(), event.source(), event.eventTime(), event.actor(),
                event.action(), event.target());
        return event;
    }

    private void validateClockRange(String eventId, Instant eventTime, String rawJson) {
        Instant now = Instant.now();
        if (eventTime.isBefore(now.minusSeconds(maxClockSkewSeconds))) {
            throw reject(TIMESTAMP_OUT_OF_RANGE, String.format(
                    "时间戳异常: 事件 %s 的时间 %s 早于接入时刻超过 %d 秒(时钟偏移容忍上限)",
                    eventId, eventTime, maxClockSkewSeconds), rawJson);
        }
        if (eventTime.isAfter(now.plusSeconds(maxFutureSeconds))) {
            throw reject(TIMESTAMP_OUT_OF_RANGE, String.format(
                    "时间戳异常: 事件 %s 的时间 %s 超前接入时刻超过 %d 秒",
                    eventId, eventTime, maxFutureSeconds), rawJson);
        }
    }

    private Instant parseTimestamp(Object raw, String rawJson) {
        if (!(raw instanceof String s) || s.isBlank()) {
            throw reject(RejectReason.INVALID_TIMESTAMP, "timestamp 必须是非空字符串", rawJson);
        }
        try {
            // ISO-8601，如 2026-09-22T10:00:00Z / 2026-09-22T18:00:00+08:00
            return Instant.parse(s);
        } catch (DateTimeParseException e1) {
            try {
                return java.time.OffsetDateTime.parse(s).toInstant();
            } catch (DateTimeParseException e2) {
                throw reject(RejectReason.INVALID_TIMESTAMP,
                        "时间戳格式非法，要求 ISO-8601(如 2026-09-22T10:00:00Z): " + s, rawJson);
            }
        }
    }

    private Object required(Map<String, Object> payload, String key, String rawJson) {
        Object v = payload.get(key);
        if (v == null || (v instanceof String s && s.isBlank())) {
            throw reject(MISSING_FIELD, "缺少必填字段: " + key, rawJson);
        }
        return v;
    }

    private String requireString(Map<String, Object> payload, String key, String rawJson) {
        Object v = required(payload, key, rawJson);
        return asString(v, key, rawJson);
    }

    private String asString(Object v, String key, String rawJson) {
        if (v instanceof String s) {
            return s;
        }
        if (v instanceof Number || v instanceof Boolean) {
            return String.valueOf(v);
        }
        throw reject(ILLEGAL_FORMAT, "字段 " + key + " 类型非法，应为字符串/数字标量", rawJson);
    }

    private String asStringOrNull(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private void putIfPresent(Map<String, String> attrs, String key,
                              Map<String, Object> payload, String rawJson) {
        Object v = payload.get(key);
        if (v != null) {
            attrs.put(key, asString(v, key, rawJson));
        }
    }

    private ValidationException reject(RejectReason reason, String message, String rawJson) {
        log.warn("归一化拒绝: reason={}, message={}, raw={}", reason, message, rawJson);
        return new ValidationException(reason, message);
    }
}
