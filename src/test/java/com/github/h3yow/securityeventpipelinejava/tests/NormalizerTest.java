package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.exception.ValidationException;
import com.github.h3yow.securityeventpipelinejava.service.JsonService;
import com.github.h3yow.securityeventpipelinejava.service.Normalizer;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.env.MockEnvironment;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 归一化单测：字段缺失 / 格式非法 / 时间戳异常必须被拒绝且原因可区分。
 * 单测日志打印输入与判定依据。
 */
class NormalizerTest {

    private static final Logger log = LoggerFactory.getLogger(NormalizerTest.class);

    private final Normalizer normalizer = new Normalizer(
            new MockEnvironment()
                    .withProperty("pipeline.max-clock-skew-seconds", "86400")
                    .withProperty("pipeline.max-future-seconds", "300"));
    private final JsonService jsonService = new JsonService(
            new com.fasterxml.jackson.databind.ObjectMapper());

    private EventIngestRequest firewall(Map<String, Object> payload) {
        return new EventIngestRequest("FIREWALL", payload);
    }

    @Test
    void normalizeValidFirewallEvent() {
        EventIngestRequest req = firewall(Map.of(
                "eventId", "evt-1",
                "timestamp", Instant.now().toString(),
                "srcIp", "10.0.0.1",
                "action", "DENY",
                "target", "10.0.0.9:22",
                "zone", "dmz"));
        log.info("[输入事件] {}", jsonService.write(req));
        var event = normalizer.normalize(req, jsonService.write(req));
        log.info("[判定依据] 归一化通过: source={}, sourceIp={}, action={}, eventTime={}",
                event.source(), event.sourceIp(), event.action(), event.eventTime());
        assertEquals("10.0.0.1", event.sourceIp());
        assertEquals("dmz", event.attributes().get("zone"));
    }

    @Test
    void rejectMissingField() {
        EventIngestRequest req = firewall(Map.of(
                "eventId", "evt-2",
                "timestamp", Instant.now().toString(),
                "action", "DENY"));
        log.info("[输入事件] {}", jsonService.write(req));
        ValidationException ex = assertThrows(ValidationException.class,
                () -> normalizer.normalize(req, jsonService.write(req)));
        log.info("[判定依据] 拒绝原因={}, message={}", ex.getReason(), ex.getMessage());
        assertEquals(RejectReason.MISSING_FIELD, ex.getReason());
    }

    @Test
    void rejectInvalidTimestampFormat() {
        EventIngestRequest req = firewall(Map.of(
                "eventId", "evt-3",
                "timestamp", "2026/09/22 10:00:00",
                "srcIp", "10.0.0.1", "action", "DENY", "target", "t:1"));
        log.info("[输入事件] {}", jsonService.write(req));
        ValidationException ex = assertThrows(ValidationException.class,
                () -> normalizer.normalize(req, jsonService.write(req)));
        log.info("[判定依据] 拒绝原因={}, message={}", ex.getReason(), ex.getMessage());
        assertEquals(RejectReason.INVALID_TIMESTAMP, ex.getReason());
    }

    @Test
    void rejectTimestampOutOfRangeTooOld() {
        EventIngestRequest req = firewall(Map.of(
                "eventId", "evt-4",
                "timestamp", Instant.now().minus(2, ChronoUnit.DAYS).toString(),
                "srcIp", "10.0.0.1", "action", "DENY", "target", "t:1"));
        log.info("[输入事件] {}", jsonService.write(req));
        ValidationException ex = assertThrows(ValidationException.class,
                () -> normalizer.normalize(req, jsonService.write(req)));
        log.info("[判定依据] 拒绝原因={}, message={}", ex.getReason(), ex.getMessage());
        assertEquals(RejectReason.TIMESTAMP_OUT_OF_RANGE, ex.getReason());
    }

    @Test
    void rejectUnknownSource() {
        EventIngestRequest req = new EventIngestRequest("WAF", Map.of("eventId", "evt-5"));
        log.info("[输入事件] {}", jsonService.write(req));
        ValidationException ex = assertThrows(ValidationException.class,
                () -> normalizer.normalize(req, jsonService.write(req)));
        log.info("[判定依据] 拒绝原因={}, message={}", ex.getReason(), ex.getMessage());
        assertEquals(RejectReason.UNKNOWN_SOURCE, ex.getReason());
    }
}
