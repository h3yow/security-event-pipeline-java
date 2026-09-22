package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.alert.Alert;
import com.github.h3yow.securityeventpipelinejava.ingest.IngestResult;
import com.github.h3yow.securityeventpipelinejava.ingest.IngestService;
import com.github.h3yow.securityeventpipelinejava.ingest.RawLogRequest;
import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.NormalizedEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 窗口关联检测：乱序、迟到、时钟偏移下判定结论稳定可解释。
 * 使用播种规则 BRUTE_FORCE_LOGIN：LOGIN_FAIL，窗口 300s，阈值 3，最大迟到 600s。
 */
@SpringBootTest
class WindowDetectionTest {

    private static final Logger log = LoggerFactory.getLogger(WindowDetectionTest.class);

    /** 对齐到窗口桶内部，避免测试时间戳跨越去重桶边界 */
    private static final long BASE_EPOCH =
            (Instant.parse("2026-09-22T12:00:00Z").getEpochSecond() / 300) * 300 + 60;

    @Autowired
    IngestService ingestService;
    @Autowired
    NormalizedEventRepository eventRepository;
    @Autowired
    AlertRepository alertRepository;

    @BeforeEach
    void clean() {
        alertRepository.deleteAll();
        eventRepository.deleteAll();
    }

    private IngestResult loginFail(String eventId, long epochOffsetSeconds, String ip) {
        Instant ts = Instant.ofEpochSecond(BASE_EPOCH + epochOffsetSeconds);
        RawLogRequest req = new RawLogRequest(EventSource.AUTH, eventId,
                "ts=" + ts + " action=LOGIN_FAIL src_ip=" + ip + " user=eve");
        IngestResult r = ingestService.ingest(req);
        log.info("input: eventId={} eventTime={} ip={} -> accepted={} reason={}",
                eventId, ts, ip, r.accepted(), r.reason());
        return r;
    }

    private void logAlerts(String ip) {
        alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals(ip))
                .forEach(a -> log.info("alert: id={} status={} hitCount={} evaluation={}",
                        a.getId(), a.getStatus(), a.getHitCount(), a.getEvaluationSnapshot()));
    }

    @Test
    void outOfOrderEventsTriggerSameConclusion() {
        String ip = "10.10.0.1";
        // 乱序到达：+20, +0, +10
        loginFail("oo-1", 20, ip);
        loginFail("oo-2", 0, ip);
        loginFail("oo-3", 10, ip);
        logAlerts(ip);

        List<Alert> alerts = alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals(ip)).toList();
        assertThat(alerts).hasSize(1);
        Alert alert = alerts.get(0);
        // 判定依据：窗口内恰好 3 个事件，达到阈值 3
        assertThat(alert.getEvaluationSnapshot()).contains("\"count\":3");
        assertThat(alert.getEvaluationSnapshot())
                .contains("oo-1").contains("oo-2").contains("oo-3");
        assertThat(alert.getHitCount()).isEqualTo(1);
    }

    @Test
    void lateEventWithinLatenessMergesIntoSameAlert() {
        String ip = "10.10.0.2";
        loginFail("lt-1", 0, ip);
        loginFail("lt-2", 10, ip);
        loginFail("lt-3", 20, ip);   // 触发告警，水位线推进到 +20
        // 迟到事件（+15，迟到 5s，在 600s 允许范围内）：重新评估后窗口仍达阈值，合并进同一告警
        IngestResult late = loginFail("lt-4", 15, ip);
        assertThat(late.accepted()).isTrue();
        logAlerts(ip);

        List<Alert> alerts = alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals(ip)).toList();
        // 触发 3 次（lt-3 自身窗口 + 迟到事件补评的 lt-4 窗口与 lt-3 窗口），
        // 全部合并进同一告警：不重复告警、计数不丢失
        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).getHitCount()).isEqualTo(3);
        assertThat(alerts.get(0).getEvaluationSnapshot()).contains("lt-4");
    }

    @Test
    void tooLateEventIsRejectedWithDistinguishableReason() {
        String ip = "10.10.0.3";
        loginFail("tl-1", 0, ip);    // 水位线 = BASE+0
        // 早于 水位线-600s 的事件被拒绝
        IngestResult tooLate = loginFail("tl-2", -601, ip);
        assertThat(tooLate.accepted()).isFalse();
        assertThat(tooLate.reason()).isEqualTo(RejectionReason.TOO_LATE);
        log.info("final state: event tl-2 rejected reason={} detail={}", tooLate.reason(), tooLate.detail());
    }

    @Test
    void eventsOutsideWindowDoNotCount() {
        String ip = "10.10.0.4";
        loginFail("ob-1", 0, ip);
        loginFail("ob-2", 10, ip);
        loginFail("ob-3", 301, ip);  // 窗口 [+1, +301] 只含 ob-3 自己
        logAlerts(ip);
        List<Alert> alerts = alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals(ip)).toList();
        assertThat(alerts).isEmpty();
    }

    @Test
    void clockSkewWithinToleranceIsAccepted() {
        String ip = "10.10.0.5";
        // 时钟偏移：事件时间比当前真实时间快 1 小时（< 24h 容忍），仍被接受
        Instant future = Instant.now().plusSeconds(3600);
        RawLogRequest req = new RawLogRequest(EventSource.AUTH, "skew-1",
                "ts=" + future + " action=LOGIN_FAIL src_ip=" + ip + " user=eve");
        IngestResult r = ingestService.ingest(req);
        log.info("input: eventId=skew-1 eventTime={} (now={}) -> accepted={} reason={}",
                future, Instant.now(), r.accepted(), r.reason());
        assertThat(r.accepted()).isTrue();
    }
}
