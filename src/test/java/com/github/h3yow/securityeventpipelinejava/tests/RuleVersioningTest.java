package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.alert.Alert;
import com.github.h3yow.securityeventpipelinejava.detection.DetectionRule;
import com.github.h3yow.securityeventpipelinejava.ingest.IngestService;
import com.github.h3yow.securityeventpipelinejava.ingest.RawLogRequest;
import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.DetectionRuleRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.NormalizedEventRepository;
import com.github.h3yow.securityeventpipelinejava.config.RuleSeeder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** 规则变更后，历史告警的判定依据（规则版本 + 窗口快照）仍可追溯。 */
@SpringBootTest
class RuleVersioningTest {

    private static final Logger log = LoggerFactory.getLogger(RuleVersioningTest.class);

    private static final long BASE_EPOCH =
            (Instant.parse("2026-09-22T12:00:00Z").getEpochSecond() / 300) * 300 + 60;

    @Autowired
    IngestService ingestService;
    @Autowired
    AlertRepository alertRepository;
    @Autowired
    NormalizedEventRepository eventRepository;
    @Autowired
    DetectionRuleRepository ruleRepository;
    @Autowired
    RuleSeeder ruleSeeder;

    @AfterEach
    void restoreRules() {
        // 恢复播种规则，避免影响其他测试
        ruleRepository.deleteAll();
        ruleSeeder.run();
    }

    @BeforeEach
    void clean() {
        alertRepository.deleteAll();
        eventRepository.deleteAll();
    }

    private void loginFail(String eventId, long offset, String ip) {
        Instant ts = Instant.ofEpochSecond(BASE_EPOCH + offset);
        ingestService.ingest(new RawLogRequest(EventSource.AUTH, eventId,
                "ts=" + ts + " action=LOGIN_FAIL src_ip=" + ip + " user=frank"));
    }

    @Test
    void alertsRemainTraceableToTheRuleVersionThatProducedThem() {
        // 规则 v1（阈值 3）下触发告警
        loginFail("rv-1", 0, "10.30.0.1");
        loginFail("rv-2", 10, "10.30.0.1");
        loginFail("rv-3", 20, "10.30.0.1");
        Alert v1Alert = alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals("10.30.0.1")).findFirst().orElseThrow();
        log.info("v1 alert: ruleVersion={} snapshot={}", v1Alert.getRuleVersion(),
                v1Alert.getEvaluationSnapshot());
        assertThat(v1Alert.getRuleVersion()).isEqualTo(1);
        assertThat(v1Alert.getEvaluationSnapshot()).contains("\"ruleVersion\":1", "\"threshold\":3");

        // 规则变更：发布 v2，阈值降为 2
        ruleRepository.save(new DetectionRule("BRUTE_FORCE_LOGIN", 2, "LOGIN_FAIL",
                300, 2, 600, true));
        log.info("rule updated: BRUTE_FORCE_LOGIN v2 threshold=2");

        // 新分组在 v2 下仅需 2 次即触发
        loginFail("rv-4", 30, "10.30.0.2");
        loginFail("rv-5", 40, "10.30.0.2");
        Alert v2Alert = alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals("10.30.0.2")).findFirst().orElseThrow();
        log.info("v2 alert: ruleVersion={} snapshot={}", v2Alert.getRuleVersion(),
                v2Alert.getEvaluationSnapshot());
        assertThat(v2Alert.getRuleVersion()).isEqualTo(2);
        assertThat(v2Alert.getEvaluationSnapshot()).contains("\"ruleVersion\":2", "\"threshold\":2");

        // 历史告警判定依据未被规则变更改写
        Alert v1Reread = alertRepository.findById(v1Alert.getId()).orElseThrow();
        assertThat(v1Reread.getRuleVersion()).isEqualTo(1);
        assertThat(v1Reread.getEvaluationSnapshot()).contains("\"ruleVersion\":1", "\"threshold\":3");
        List<Alert> all = alertRepository.findAll();
        log.info("final state: {} alerts, versions={}", all.size(),
                all.stream().map(Alert::getRuleVersion).toList());
    }
}
