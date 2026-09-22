package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.common.RuleAction;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import com.github.h3yow.securityeventpipelinejava.service.JsonService;
import com.github.h3yow.securityeventpipelinejava.service.RuleService;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import com.github.h3yow.securityeventpipelinejava.web.RuleUpsertRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则版本化测试：规则变更产生新版本，旧版本保留；
 * 历史告警记录命中时的版本与规则快照，判定依据可追溯。
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class RuleVersioningTest {

    private static final Logger log = LoggerFactory.getLogger(RuleVersioningTest.class);

    @Autowired private IngestionService ingestionService;
    @Autowired private RuleService ruleService;
    @Autowired private AlertRepository alertRepository;
    @Autowired private WindowAggregateRepository windowAggregateRepository;
    @Autowired private WindowEventRepository windowEventRepository;
    @Autowired private EventRepository eventRepository;
    @Autowired private RejectedEventRepository rejectedEventRepository;
    @Autowired private JsonService jsonService;

    @Autowired private com.github.h3yow.securityeventpipelinejava.repository.RuleRepository ruleRepository;

    private static final String TEST_RULE = "RV_TEST_SCAN";

    @BeforeEach
    void clean() {
        alertRepository.deleteAllInBatch();
        windowAggregateRepository.deleteAllInBatch();
        windowEventRepository.deleteAllInBatch();
        rejectedEventRepository.deleteAllInBatch();
        eventRepository.deleteAllInBatch();
        ruleRepository.findByRuleCodeOrderByVersionDesc(TEST_RULE)
                .forEach(ruleRepository::delete);
    }

    private EventIngestRequest deny(String id, Instant ts, String ip) {
        return new EventIngestRequest("FIREWALL", Map.of(
                "eventId", id, "timestamp", ts.toString(),
                "srcIp", ip, "action", "DENY", "target", "10.0.0.9:22"));
    }

    @Test
    void alertKeepsRuleVersionAndSnapshotAfterRuleChange() {
        // 0) 创建测试专用规则 v1(阈值4)
        ruleService.createOrUpdate(new RuleUpsertRequest(
                TEST_RULE, "版本化测试规则",
                Map.of("action", "DENY"),
                "sourceIp", 60L, 120L, 4, RuleAction.ALERT.name(), 180L, true));

        // 1) 用 v1(阈值4) 命中产生告警（固定在当前 60s 窗口内）
        Instant base = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES);
        for (int i = 1; i <= 4; i++) {
            ingestionService.ingest(deny("rv-" + i, base.plusSeconds(10 + i), "192.168.0.7"));
        }
        AlertEntity alertBefore = alertRepository.findAll().stream()
                .filter(a -> a.getRuleCode().equals(TEST_RULE)).findFirst().orElseThrow();
        log.info("[变更前] 告警 ruleCode={}, ruleVersion={}, 快照={}",
                alertBefore.getRuleCode(), alertBefore.getRuleVersion(),
                alertBefore.getRuleSnapshotJson());
        assertEquals(1, alertBefore.getRuleVersion());
        assertTrue(alertBefore.getRuleSnapshotJson().contains("\"threshold\":4"));

        long v1RuleId = alertBefore.getRuleId();

        // 2) 规则变更：阈值 4 -> 2，产生 v2
        RuleEntity v2 = ruleService.createOrUpdate(new RuleUpsertRequest(
                TEST_RULE, "版本化测试规则",
                Map.of("action", "DENY"),
                "sourceIp", 60L, 120L, 2, RuleAction.ALERT.name(), 180L, true));
        log.info("[规则变更] 新版本 id={}, version={}, threshold={}",
                v2.getId(), v2.getVersion(), v2.getThreshold());
        assertEquals(2, v2.getVersion());
        assertTrue(ruleService.history(TEST_RULE).size() >= 2, "历史版本必须保留");

        // 3) 历史告警仍引用 v1 的 ruleId/版本/快照，不随规则变更而改变
        AlertEntity alertAfter = alertRepository.findById(alertBefore.getId()).orElseThrow();
        log.info("[变更后复查历史告警] ruleVersion={}, ruleId={} 仍指向 v1 行 id={}, 快照阈值=4",
                alertAfter.getRuleVersion(), alertAfter.getRuleId(), v1RuleId);
        assertEquals(1, alertAfter.getRuleVersion(), "历史告警判定依据版本不得被规则变更改写");
        assertEquals(v1RuleId, alertAfter.getRuleId());
        assertTrue(alertAfter.getRuleSnapshotJson().contains("\"threshold\":4"));

        // 4) 新事件按 v2 判定（阈值 2 即触发），新窗口关联新规则行
        Instant base2 = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES);
        ingestionService.ingest(deny("rv-new-1", base2.plusSeconds(40), "192.168.0.8"));
        ingestionService.ingest(deny("rv-new-2", base2.plusSeconds(42), "192.168.0.8"));
        WindowAggregateJsonCheck check = new WindowAggregateJsonCheck();
        long v2RuleId = v2.getId();
        windowAggregateRepository.findAll().stream()
                .filter(w -> w.getRuleId() == v2RuleId)
                .findFirst().ifPresent(w -> {
                    log.info("[新版本判定依据] 新窗口 version={}, count={}, threshold={}, fired={}",
                            w.getVersion(), w.getCount(), w.getThreshold(), w.isFired());
                    check.version = w.getVersion();
                    check.threshold = w.getThreshold();
                    check.fired = w.isFired();
                });
        assertEquals(2, check.version, "新事件必须按规则 v2 判定");
        assertEquals(2, check.threshold);
        assertTrue(check.fired);
    }

    private static class WindowAggregateJsonCheck {
        int version;
        int threshold;
        boolean fired;
    }
}
