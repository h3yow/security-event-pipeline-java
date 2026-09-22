package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.ingest.IngestResult;
import com.github.h3yow.securityeventpipelinejava.ingest.IngestService;
import com.github.h3yow.securityeventpipelinejava.ingest.RawLogRequest;
import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.model.RejectedEvent;
import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.NormalizedEventRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.RejectedEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** 归一化：字段缺失 / 格式非法 / 时间戳异常必须被拒绝且原因可区分，且留痕不静默丢弃。 */
@SpringBootTest
class NormalizationIngestTest {

    private static final Logger log = LoggerFactory.getLogger(NormalizationIngestTest.class);

    @Autowired
    IngestService ingestService;
    @Autowired
    RejectedEventRepository rejectedEventRepository;
    @Autowired
    NormalizedEventRepository eventRepository;
    @Autowired
    AlertRepository alertRepository;

    @BeforeEach
    void clean() {
        // 清理事件与告警，重置水位线，避免测试间相互影响
        alertRepository.deleteAll();
        eventRepository.deleteAll();
        rejectedEventRepository.deleteAll();
    }

    private IngestResult ingestAndLog(RawLogRequest req) {
        IngestResult result = ingestService.ingest(req);
        log.info("input={} -> accepted={} reason={} detail={}",
                req, result.accepted(), result.reason(), result.detail());
        return result;
    }

    @Test
    void missingFieldIsRejectedWithDistinguishableReason() {
        IngestResult r = ingestAndLog(new RawLogRequest(EventSource.AUTH, "m1",
                "ts=2026-09-22T10:00:00Z src_ip=10.1.0.1")); // 缺 action
        assertThat(r.accepted()).isFalse();
        assertThat(r.reason()).isEqualTo(RejectionReason.MISSING_FIELD);

        IngestResult r2 = ingestAndLog(new RawLogRequest(EventSource.AUTH, "m2", null)); // 缺 payload
        assertThat(r2.reason()).isEqualTo(RejectionReason.MISSING_FIELD);
    }

    @Test
    void invalidFormatIsRejectedWithDistinguishableReason() {
        IngestResult r = ingestAndLog(new RawLogRequest(EventSource.FIREWALL, "f1",
                "{not valid json"));
        assertThat(r.accepted()).isFalse();
        assertThat(r.reason()).isEqualTo(RejectionReason.INVALID_FORMAT);

        IngestResult r2 = ingestAndLog(new RawLogRequest(EventSource.AUTH, "f2",
                "this-is-not-kv"));
        assertThat(r2.reason()).isEqualTo(RejectionReason.INVALID_FORMAT);
    }

    @Test
    void abnormalTimestampIsRejectedWithDistinguishableReason() {
        // 无法解析的时间戳
        IngestResult r = ingestAndLog(new RawLogRequest(EventSource.FIREWALL, "t1",
                "{\"ts\":\"not-a-time\",\"action\":\"CONNECTION_DENIED\",\"src_ip\":\"1.1.1.1\"}"));
        assertThat(r.reason()).isEqualTo(RejectionReason.INVALID_TIMESTAMP);

        // 超出合理下界的时间戳
        IngestResult r2 = ingestAndLog(new RawLogRequest(EventSource.FIREWALL, "t2",
                "{\"ts\":\"1999-01-01T00:00:00Z\",\"action\":\"CONNECTION_DENIED\",\"src_ip\":\"1.1.1.1\"}"));
        assertThat(r2.reason()).isEqualTo(RejectionReason.INVALID_TIMESTAMP);

        // 时钟偏移过大（未来超过 24h）
        IngestResult r3 = ingestAndLog(new RawLogRequest(EventSource.FIREWALL, "t3",
                "{\"ts\":\"2099-01-01T00:00:00Z\",\"action\":\"CONNECTION_DENIED\",\"src_ip\":\"1.1.1.1\"}"));
        assertThat(r3.reason()).isEqualTo(RejectionReason.INVALID_TIMESTAMP);
    }

    @Test
    void rejectedRecordsArePersistedForAudit() {
        ingestAndLog(new RawLogRequest(EventSource.AUTH, "p1", "bad-token"));
        ingestAndLog(new RawLogRequest(EventSource.FIREWALL, "p2", "{}"));
        List<RejectedEvent> rejected = rejectedEventRepository.findAll();
        rejected.forEach(e -> log.info("persisted rejection: eventId={} reason={} detail={}",
                e.getEventId(), e.getReason(), e.getDetail()));
        assertThat(rejected).hasSize(2);
        assertThat(rejected).extracting(RejectedEvent::getReason)
                .containsExactlyInAnyOrder(RejectionReason.INVALID_FORMAT, RejectionReason.MISSING_FIELD);
    }

    @Test
    void multiSourcePayloadsNormalizeToSameModel() {
        IngestResult fw = ingestAndLog(new RawLogRequest(EventSource.FIREWALL, "n1",
                "{\"ts\":\"2026-09-22T10:00:00Z\",\"action\":\"CONNECTION_DENIED\",\"src_ip\":\"9.9.9.1\"}"));
        IngestResult ids = ingestAndLog(new RawLogRequest(EventSource.IDS, "n2",
                "{\"timestamp\":\"2026-09-22T10:00:01Z\",\"signature\":\"port_scan\",\"src\":\"9.9.9.2\"}"));
        IngestResult auth = ingestAndLog(new RawLogRequest(EventSource.AUTH, "n3",
                "ts=2026-09-22T10:00:02Z action=LOGIN_SUCCESS src_ip=9.9.9.3 user=bob"));
        assertThat(fw.accepted()).isTrue();
        assertThat(ids.accepted()).isTrue();
        assertThat(auth.accepted()).isTrue();
    }
}
