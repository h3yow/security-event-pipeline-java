package com.github.h3yow.securityeventpipelinejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.model.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * 防火墙 JSON 日志解析器。
 * 报文示例：{"ts":"2026-09-22T10:00:00Z","action":"CONNECTION_DENIED","src_ip":"10.0.0.1","user":"alice"}
 * 必填：ts, action, src_ip；可选：user。
 */
@Component
public class FirewallJsonNormalizer implements LogNormalizer {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public EventSource supportedSource() {
        return EventSource.FIREWALL;
    }

    @Override
    public NormalizedEvent normalize(String eventId, String payload) throws NormalizationException {
        JsonNode root;
        try {
            root = MAPPER.readTree(payload);
        } catch (Exception e) {
            throw new NormalizationException(RejectionReason.INVALID_FORMAT,
                    "payload is not valid JSON: " + e.getMessage());
        }
        if (root == null || !root.isObject()) {
            throw new NormalizationException(RejectionReason.INVALID_FORMAT, "payload is not a JSON object");
        }
        Instant ts = TimestampParser.parse(root.has("ts") ? readValue(root.get("ts")) : null);
        String action = requiredText(root, "action");
        String srcIp = requiredText(root, "src_ip");
        String user = optionalText(root, "user");
        return new NormalizedEvent(eventId, supportedSource(), action, ts, Instant.now(),
                srcIp, user, payload);
    }

    static String requiredText(JsonNode root, String field) throws NormalizationException {
        String v = optionalText(root, field);
        if (v == null) {
            throw new NormalizationException(RejectionReason.MISSING_FIELD,
                    "required field missing or blank: " + field);
        }
        return v;
    }

    static String optionalText(JsonNode root, String field) {
        JsonNode n = root.get(field);
        if (n == null || n.isNull()) {
            return null;
        }
        String v = n.asText().trim();
        return v.isEmpty() ? null : v;
    }

    private static Object readValue(JsonNode n) {
        if (n == null || n.isNull()) {
            return null;
        }
        return n.isNumber() ? n.longValue() : n.asText();
    }
}
