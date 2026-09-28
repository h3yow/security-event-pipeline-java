package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliation;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliationReport;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import com.github.h3yow.securityeventpipelinejava.service.JsonService;
import com.github.h3yow.securityeventpipelinejava.service.ReconciliationService;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 窗口对账查询测试：正常窗口一致；人为制造差异（计数漂移、关联缺失、孤儿关联、误报/漏告警）
 * 必须被逐条识别，而不是只给总数。
 */
@SpringBootTest
class ReconciliationQueryTest {

    private static final Logger log = LoggerFactory.getLogger(ReconciliationQueryTest.class);

    @Autowired private IngestionService ingestionService;
    @Autowired private ReconciliationService reconciliationService;
    @Autowired private EventRepository eventRepository;
    @Autowired private AlertRepository alertRepository;
    @Autowired private RejectedEventRepository rejectedEventRepository;
    @Autowired private WindowAggregateRepository windowAggregateRepository;
    @Autowired private WindowEventRepository windowEventRepository;
    @Autowired private JsonService jsonService;

    @BeforeEach
    void clean() {
        alertRepository.deleteAllInBatch();
        windowAggregateRepository.deleteAllInBatch();
        windowEventRepository.deleteAllInBatch();
        rejectedEventRepository.deleteAllInBatch();
        eventRepository.deleteAllInBatch();
    }

    private EventIngestRequest auth(String id, Instant ts, String user) {
        return new EventIngestRequest("AUTH", Map.of(
                "eventId", id, "timestamp", ts.toString(),
                "username", user, "result", "LOGIN_FAIL", "service", "ssh"));
    }

    @Test
    void healthyWindowIsConsistentAndReportIsExplainable() {
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(10);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("rc-ok-" + i, ts.plusSeconds(i), "olivia"));
        }
        log.info("[输入事件] rc-ok-1..3 同窗口同分组，阈值 3");

        WindowReconciliationReport report =
                reconciliationService.reconcile("AUTH_BRUTE_FORCE", null, "olivia", null, null);
        WindowReconciliation w = report.windows().get(0);
        log.info("[判定依据] storedCount={}, actualUnique={}, expected={}, fired={}/shouldFire={}, 贡献条数={}",
                w.storedCount(), w.actualUniqueCount(), w.expectedCount(), w.fired(), w.shouldFire(),
                w.contributions().size());
        log.info("[最终状态] consistent={}, matchedAlertId={}, contributions={}",
                w.consistent(), w.matchedAlertId(),
                w.contributions().stream().map(c -> c.eventId() + ":" + c.category()).toList());

        assertEquals(1, report.totalWindows());
        assertEquals(0, report.inconsistentWindows());
        assertTrue(w.consistent());
        assertEquals(3, w.storedCount());
        assertEquals(3, w.actualUniqueCount());
        assertEquals(3, w.expectedCount());
        assertTrue(w.fired());
        assertTrue(w.shouldFire());
        assertEquals(3, w.contributions().size());
        assertTrue(w.contributions().stream().allMatch(c -> c.category().equals("COUNTED")));
    }

    @Test
    void discrepanciesAreItemizedNotJustTotals() {
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(10);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("rc-bad-" + i, ts.plusSeconds(i), "penny"));
        }
        WindowAggregateEntity agg = windowAggregateRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals("penny")).findFirst().orElseThrow();
        String windowKey = agg.getRuleId() + "#v" + agg.getVersion() + "#penny#" + agg.getWindowStart();

        // 人为漂移 1：删掉一条窗口关联（模拟少算），并把统计值改成 5（漂移）
        WindowEventEntity row = windowEventRepository
                .findByRuleIdAndWindowKeyOrderByEventIdAsc(agg.getRuleId(), windowKey).get(0);
        String removedId = row.getEventId();
        windowEventRepository.deleteById(row.getId());
        windowEventRepository.flush();
        agg.setCount(5);
        windowAggregateRepository.saveAndFlush(agg);
        log.info("[输入差异] 删除关联 {} (missing)，并把 count 从 3 改为 5", removedId);

        // 人为漂移 2：插一条本窗口不应存在的孤儿关联（eventId 根本不存在于已受理事件）
        windowEventRepository.saveAndFlush(new WindowEventEntity(agg.getRuleId(), windowKey, "ghost-event"));
        log.info("[输入差异] 插入孤儿关联 ghost-event (orphan)");

        WindowReconciliationReport report =
                reconciliationService.reconcile("AUTH_BRUTE_FORCE", agg.getVersion(), "penny", null, null);
        WindowReconciliation w = report.windows().get(0);
        log.info("[判定依据] storedCount={}, actualUnique={}, expected={}",
                w.storedCount(), w.actualUniqueCount(), w.expectedCount());
        log.info("[最终状态] consistent={}, missing={}, orphan={}, countMismatch={}, 贡献分类={}",
                w.consistent(), w.missingEventIds(), w.orphanEventIds(), w.countMismatch(),
                w.contributions().stream().map(c -> c.eventId() + ":" + c.category()).toList());

        assertFalse(w.consistent());
        assertTrue(w.countMismatch());
        assertEquals(List.of(removedId), w.missingEventIds(), "必须逐条指出少算了哪个事件");
        assertEquals(List.of("ghost-event"), w.orphanEventIds(), "必须逐条指出多算了哪个事件");
        assertEquals(5, w.storedCount());
        assertEquals(3, w.actualUniqueCount(), "关联行数=剩2+孤儿1");
        assertEquals(3, w.expectedCount());
        assertTrue(w.contributions().stream().anyMatch(c -> c.eventId().equals(removedId) && c.category().equals("MISSING")));
        assertTrue(w.contributions().stream().anyMatch(c -> c.eventId().equals("ghost-event") && c.category().equals("ORPHAN")));
    }
}
