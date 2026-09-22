package com.github.h3yow.securityeventpipelinejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.model.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * IDS JSON 日志解析器（字段名与防火墙不同，体现多源归一化）。
 * 报文示例：{"timestamp":"2026-09-22T10:00:00Z","signature":"PORT_SCAN","src":"10.0.0.9","user":null}
 * 必填：timestamp, signature, src；可选：user。action 归一化为 signature 大写。
 */
@Component
public class IdsJsonNormalizer implements LogNormalizer {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public EventSource supportedSource() {
        return EventSource.IDS;
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
        JsonNode tsNode = root.get("timestamp");
        Instant ts = TimestampParser.parse(
                tsNode == null || tsNode.isNull() ? null
                        : tsNode.isNumber() ? tsNode.longValue() : tsNode.asText());
        String signature = FirewallJsonNormalizer.requiredText(root, "signature");
        String src = FirewallJsonNormalizer.requiredText(root, "src");
        String user = FirewallJsonNormalizer.optionalText(root, "user");
        return new NormalizedEvent(eventId, supportedSource(), signature.toUpperCase(), ts,
                Instant.now(), src, user, payload);
    }
}
