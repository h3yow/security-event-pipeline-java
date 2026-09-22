package com.github.h3yow.securityeventpipelinejava.ingest;

import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.model.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 认证日志解析器，key=value 空格分隔文本。
 * 报文示例：ts=2026-09-22T10:00:00Z action=LOGIN_FAIL src_ip=10.0.0.1 user=alice
 * 必填：ts, action, src_ip；可选：user。
 */
@Component
public class AuthLogNormalizer implements LogNormalizer {

    @Override
    public EventSource supportedSource() {
        return EventSource.AUTH;
    }

    @Override
    public NormalizedEvent normalize(String eventId, String payload) throws NormalizationException {
        if (payload == null || payload.isBlank()) {
            throw new NormalizationException(RejectionReason.INVALID_FORMAT, "payload is blank");
        }
        Map<String, String> kv = new LinkedHashMap<>();
        for (String token : payload.trim().split("\\s+")) {
            int eq = token.indexOf('=');
            if (eq <= 0) {
                throw new NormalizationException(RejectionReason.INVALID_FORMAT,
                        "token is not key=value: " + token);
            }
            kv.put(token.substring(0, eq), token.substring(eq + 1));
        }
        Instant ts = TimestampParser.parse(kv.get("ts"));
        String action = required(kv, "action");
        String srcIp = required(kv, "src_ip");
        String user = kv.getOrDefault("user", null);
        if (user != null && user.isBlank()) {
            user = null;
        }
        return new NormalizedEvent(eventId, supportedSource(), action, ts, Instant.now(),
                srcIp, user, payload);
    }

    private static String required(Map<String, String> kv, String field) throws NormalizationException {
        String v = kv.get(field);
        if (v == null || v.isBlank()) {
            throw new NormalizationException(RejectionReason.MISSING_FIELD,
                    "required field missing or blank: " + field);
        }
        return v;
    }
}
