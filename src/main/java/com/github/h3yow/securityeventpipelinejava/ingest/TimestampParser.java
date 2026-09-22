package com.github.h3yow.securityeventpipelinejava.ingest;

import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/** 时间戳解析与合理性校验：支持 ISO-8601 字符串与 epoch 毫秒/秒数字。 */
final class TimestampParser {

    /** 合理下界：早于该时间视为异常时间戳 */
    private static final Instant LOWER_BOUND = Instant.parse("2020-01-01T00:00:00Z");
    /** 合理上界：允许的最大未来时钟偏移 */
    private static final long MAX_FUTURE_SKEW_SECONDS = 24 * 3600;

    private TimestampParser() {}

    /**
     * 解析时间戳字段。
     *
     * @param raw 原始值（字符串或数字）
     * @return 事件时间
     * @throws NormalizationException 值为 null 时 MISSING_FIELD；无法解析或超出合理范围时 INVALID_TIMESTAMP
     */
    static Instant parse(Object raw) throws NormalizationException {
        if (raw == null) {
            throw new NormalizationException(RejectionReason.MISSING_FIELD, "timestamp field is missing");
        }
        Instant ts;
        if (raw instanceof Number num) {
            ts = fromEpoch(num.longValue());
        } else {
            String s = raw.toString().trim();
            if (s.isEmpty()) {
                throw new NormalizationException(RejectionReason.INVALID_TIMESTAMP, "timestamp is blank");
            }
            if (s.matches("-?\\d+")) {
                ts = fromEpoch(Long.parseLong(s));
            } else {
                try {
                    ts = Instant.parse(s);
                } catch (DateTimeParseException e) {
                    throw new NormalizationException(RejectionReason.INVALID_TIMESTAMP,
                            "timestamp not ISO-8601: " + s);
                }
            }
        }
        validateRange(ts);
        return ts;
    }

    /** epoch 毫秒（13 位）或秒（10 位）自动识别。 */
    private static Instant fromEpoch(long v) throws NormalizationException {
        if (v > 100_000_000_000L) {
            return Instant.ofEpochMilli(v);
        }
        if (v > 0) {
            return Instant.ofEpochSecond(v);
        }
        throw new NormalizationException(RejectionReason.INVALID_TIMESTAMP, "negative epoch: " + v);
    }

    private static void validateRange(Instant ts) throws NormalizationException {
        if (ts.isBefore(LOWER_BOUND)) {
            throw new NormalizationException(RejectionReason.INVALID_TIMESTAMP,
                    "timestamp before reasonable lower bound: " + ts);
        }
        Instant upper = Instant.now().plusSeconds(MAX_FUTURE_SKEW_SECONDS);
        if (ts.isAfter(upper)) {
            throw new NormalizationException(RejectionReason.INVALID_TIMESTAMP,
                    "timestamp too far in future (clock skew > 24h): " + ts);
        }
    }
}
