package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.common.AlertStatus;
import com.github.h3yow.securityeventpipelinejava.domain.recon.RepairResult;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliation;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliationReport;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowRepairAction;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RepairAuditEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RepairAuditRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import com.github.h3yow.securityeventpipelinejava.service.ReconciliationService;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import com.github.h3yow.securityeventpipelinejava.web.WindowRepairRequest;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 窗口自愈测试：修复幂等（重复触发结果一致）、漏报补建、误报删除、并发修复收敛，
 * 以及"补录后并发修复"场景下计数/告警最终一致。日志包含输入、判定依据、最终结果。
 */
@SpringBootTest
class WindowSelfHealTest {

    private static final Logger log = LoggerFactory.getLogger(WindowSelfHealTest.class);

    @Autowired private IngestionService ingestionService;
    @Autowired private ReconciliationService reconciliationService;
    @Autowired private EventRepository eventRepository;
    @Autowired private AlertRepository alertRepository;
    @Autowired private RejectedEventRepository rejectedEventRepository;
    @Autowired private WindowAggregateRepository windowAggregateRepository;
    @Autowired private WindowEventRepository windowEventRepository;
    @Autowired private RepairAuditRepository repairAuditRepository;

    @BeforeEach
    void clean() {
        repairAuditRepository.deleteAllInBatch();
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

    private WindowRepairRequest repairFor(String group) {
        return new WindowRepairRequest("AUTH_BRUTE_FORCE", null, group, null, null,
                true, "对账发现窗口统计与去重事件不一致");
    }

    private WindowAggregateEntity windowOf(String group) {
        return windowAggregateRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals(group)).findFirst().orElseThrow();
    }

    @Test
    void repairConvergesCountAndIsIdempotentAcrossRepeatedRuns() {
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(10);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("he-1-" + i, ts.plusSeconds(i), "quinn"));
        }
        WindowAggregateEntity agg = windowOf("quinn");
        // 人为漂移：删一条关联 + count 改成 9
        WindowEventEntity row = windowEventRepository
                .findByRuleIdAndWindowKeyOrderByEventIdAsc(
                        agg.getRuleId(), agg.getRuleId() + "#v" + agg.getVersion()
                                + "#quinn#" + agg.getWindowStart()).get(0);
        String removed = row.getEventId();
        windowEventRepository.deleteById(row.getId());
        windowEventRepository.flush();
        agg.setCount(9);
        windowAggregateRepository.saveAndFlush(agg);
        log.info("[输入差异] quinn 窗口删除关联 {}，count 置为 9", removed);

        RepairResult first = reconciliationService.repair(repairFor("quinn"), "ops-1", "ADMIN");
        log.info("[判定依据] 第一次修复 changed={}, actions={}", first.changedWindows(),
                first.actions().stream().map(WindowRepairAction::actions).toList());

        WindowAggregateEntity after1 = windowOf("quinn");
        assertEquals(3, after1.getCount(), "统计必须收敛到去重事件数 3");
        assertTrue(after1.isFired());
        assertNotNull(after1.getMatchedAlertId(), "达到阈值必须有告警");

        WindowReconciliationReport report =
                reconciliationService.reconcile("AUTH_BRUTE_FORCE", null, "quinn", null, null);
        assertTrue(report.windows().get(0).consistent(), "修复后对账必须一致");

        // 再次修复：幂等空跑，0 变更；状态完全不变
        long alertsBefore = alertRepository.findAll().stream().filter(a -> a.getGroupKey().equals("quinn")).count();
        RepairResult second = reconciliationService.repair(repairFor("quinn"), "ops-1", "ADMIN");
        RepairResult third = reconciliationService.repair(repairFor("quinn"), "ops-1", "ADMIN");
        WindowAggregateEntity after3 = windowOf("quinn");
        long alertsAfter = alertRepository.findAll().stream().filter(a -> a.getGroupKey().equals("quinn")).count();
        log.info("[最终状态] 第二/三次修复 changed={}/{}，count={}, fired={}, alertId={}, 告警数 {}->{}",
                second.changedWindows(), third.changedWindows(), after3.getCount(), after3.isFired(),
                after3.getMatchedAlertId(), alertsBefore, alertsAfter);

        assertEquals(0, second.changedWindows(), "重复修复必须幂等：无变更");
        assertEquals(0, third.changedWindows(), "第三次修复同样无变更");
        assertEquals(3, after3.getCount());
        assertEquals(alertsBefore, alertsAfter, "重复修复不得重复建警");
        assertEquals(1, alertsAfter);
        // 每次触发都留审计（含空跑）
        List<RepairAuditEntity> audits = repairAuditRepository.findAll();
        assertEquals(3, audits.size(), "重复/幂等触发都必须留审计记录");
    }

    @Test
    void belowThresholdFalseAlertIsRemovedAndNotRecreated() {
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(10);
        // 只受理 2 条（阈值 3，本不该触发）
        for (int i = 1; i <= 2; i++) {
            ingestionService.ingest(auth("he-2-" + i, ts.plusSeconds(i), "ruth"));
        }
        WindowAggregateEntity agg = windowOf("ruth");
        // 人为制造误报：强行 fired=true，count=3，并插一条幽灵事件
        String wk = agg.getRuleId() + "#v" + agg.getVersion() + "#ruth#" + agg.getWindowStart();
        windowEventRepository.saveAndFlush(new WindowEventEntity(agg.getRuleId(), wk, "ghost-2"));
        agg.setCount(3);
        agg.setFired(true);
        windowAggregateRepository.saveAndFlush(agg);
        // 再为该窗口伪造一条告警（模拟误报已建）
        AlertEntity falseAlert = new AlertEntity();
        falseAlert.setRuleId(agg.getRuleId());
        falseAlert.setRuleVersion(agg.getVersion());
        falseAlert.setRuleCode("AUTH_BRUTE_FORCE");
        falseAlert.setRuleSnapshotJson("{}");
        falseAlert.setGroupKey("ruth");
        falseAlert.setStatus(AlertStatus.OPEN.name());
        falseAlert.setOccurrenceCount(1);
        falseAlert.getWindowKeys().add(wk);
        falseAlert.setFirstEventTime(ts);
        falseAlert.setLastEventTime(ts);
        falseAlert.setCreatedAt(Instant.now());
        falseAlert.setUpdatedAt(Instant.now());
        falseAlert = alertRepository.saveAndFlush(falseAlert);
        agg.setMatchedAlertId(falseAlert.getId());
        windowAggregateRepository.saveAndFlush(agg);
        long falseAlertId = falseAlert.getId();
        log.info("[输入差异] ruth 窗口实际仅 2 事件，伪造 fired/count=3 与误报告警 {}", falseAlertId);

        RepairResult result = reconciliationService.repair(repairFor("ruth"), "ops-2", "ADMIN");
        log.info("[判定依据] 修复 actions={}", result.actions().stream()
                .map(a -> a.actions() + ":" + a.note()).toList());

        WindowAggregateEntity after = windowOf("ruth");
        log.info("[最终状态] count={}, fired={}, matchedAlertId={}, 误报告警存在={}",
                after.getCount(), after.isFired(), after.getMatchedAlertId(),
                alertRepository.findById(falseAlertId).isPresent());
        assertEquals(2, after.getCount(), "收敛到真实去重事件数 2");
        assertEquals(false, after.isFired(), "未达阈值不得保持触发");
        assertNull(after.getMatchedAlertId(), "未达阈值不得关联告警");
        assertTrue(alertRepository.findById(falseAlertId).isEmpty(), "纯自动误报告警应被删除");
        assertEquals(0, alertRepository.findAll().stream().filter(a -> a.getGroupKey().equals("ruth")).count());

        // 再次修复：不会把告警建回来
        reconciliationService.repair(repairFor("ruth"), "ops-2", "ADMIN");
        assertEquals(0, alertRepository.findAll().stream().filter(a -> a.getGroupKey().equals("ruth")).count(),
                "幂等修复不得重新建警");
    }

    @Test
    void concurrentRepairsConvergeToSameResult() throws Exception {
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(10);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("he-3-" + i, ts.plusSeconds(i), "sam"));
        }
        WindowAggregateEntity agg = windowOf("sam");
        WindowEventEntity row = windowEventRepository
                .findByRuleIdAndWindowKeyOrderByEventIdAsc(
                        agg.getRuleId(), agg.getRuleId() + "#v" + agg.getVersion()
                                + "#sam#" + agg.getWindowStart()).get(0);
        windowEventRepository.deleteById(row.getId());
        windowEventRepository.flush();
        agg.setCount(1);
        windowAggregateRepository.saveAndFlush(agg);
        log.info("[输入差异] sam 窗口删除一条关联、count=1，随后 8 个并发修复");

        int n = 8;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        for (int i = 0; i < n; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    reconciliationService.repair(repairFor("sam"), "ops-3", "ADMIN");
                } catch (Exception e) {
                    log.error("并发修复异常", e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        WindowAggregateEntity after = windowOf("sam");
        long samAlerts = alertRepository.findAll().stream().filter(a -> a.getGroupKey().equals("sam")).count();
        long changedRuns = repairAuditRepository.findAll().stream()
                .filter(a -> a.getChangedWindows() > 0).count();
        log.info("[最终状态] count={}, fired={}, alertId={}, sam 告警数={}, 有变更的修复次数={}, 审计总数={}",
                after.getCount(), after.isFired(), after.getMatchedAlertId(),
                samAlerts, changedRuns, repairAuditRepository.count());

        assertEquals(3, after.getCount(), "并发修复后统计必须收敛到 3");
        assertEquals(1, samAlerts, "并发修复至多创建一条告警，不重复建警");
        assertEquals(1, changedRuns, "8 次并发修复中只有第一次产生变更，其余幂等");
        assertEquals(n, repairAuditRepository.count(), "每次触发都留审计");
        WindowReconciliation r = reconciliationService
                .reconcile("AUTH_BRUTE_FORCE", null, "sam", null, null).windows().get(0);
        assertTrue(r.consistent());
    }

    @Test
    void orphanWindowMembershipInMergedAlertIsDetectedAndCleared() {
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(10);
        // tina 窗口只有 2 条（未达阈值）
        for (int i = 1; i <= 2; i++) {
            ingestionService.ingest(auth("he-4-" + i, ts.plusSeconds(i), "tina"));
        }
        WindowAggregateEntity tina = windowOf("tina");
        String tinaKey = tina.getRuleId() + "#v" + tina.getVersion() + "#tina#" + tina.getWindowStart();
        // 另一个真实命中的窗口 uma（3 条），产生一条合并告警
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("he-4-uma-" + i, ts.plusSeconds(i), "uma"));
        }
        AlertEntity umaAlert = alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals("uma")).findFirst().orElseThrow();
        // 漂移：tina 未达阈值，却被错误塞进了 uma 的告警（注意不是 tina 自己的关联）
        umaAlert.getWindowKeys().add(tinaKey);
        umaAlert.setOccurrenceCount(umaAlert.getOccurrenceCount() + 1);
        alertRepository.saveAndFlush(umaAlert);
        log.info("[输入差异] tina 窗口仅 2 事件未达阈值，但被错误并入告警 {} (occurrenceCount={})",
                umaAlert.getId(), umaAlert.getOccurrenceCount());

        WindowReconciliation before = reconciliationService
                .reconcile("AUTH_BRUTE_FORCE", null, "tina", null, null).windows().get(0);
        log.info("[判定依据] 修复前 consistent={}, alertNotApplicable={}, shouldFire={}",
                before.consistent(), before.alertNotApplicable(), before.shouldFire());
        assertEquals(false, before.consistent());
        assertTrue(before.alertNotApplicable());

        reconciliationService.repair(repairFor("tina"), "ops-4", "ADMIN");

        AlertEntity afterAlert = alertRepository.findById(umaAlert.getId()).orElseThrow();
        log.info("[最终状态] 修复后告警 {} 仍存在={}, 仍含 tina 窗口={}, occurrenceCount={}",
                umaAlert.getId(), true, afterAlert.getWindowKeys().contains(tinaKey),
                afterAlert.getOccurrenceCount());
        assertEquals(false, afterAlert.getWindowKeys().contains(tinaKey), "错误归属必须解除");
        assertEquals(1, afterAlert.getOccurrenceCount(), "合并次数必须回退为 1");
        WindowReconciliation after = reconciliationService
                .reconcile("AUTH_BRUTE_FORCE", null, "tina", null, null).windows().get(0);
        assertTrue(after.consistent(), "修复后 tina 窗口一致，且未误删 uma 的真实告警");
    }
}
