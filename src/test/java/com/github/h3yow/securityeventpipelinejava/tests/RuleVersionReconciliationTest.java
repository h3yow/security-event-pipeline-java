package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.common.RuleAction;
import com.github.h3yow.securityeventpipelinejava.domain.recon.RepairResult;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliation;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliationReport;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.exception.PipelineException;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RepairAuditRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import com.github.h3yow.securityeventpipelinejava.service.ReconciliationService;
import com.github.h3yow.securityeventpipelinejava.service.RuleService;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import com.github.h3yow.securityeventpipelinejava.web.RuleUpsertRequest;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则升级场景下的按版本窗口对账与自愈测试。
 *
 * <p>核心归属口径：事件只计入它<b>受理时生效</b>的规则版本窗口——
 * v 版本生效区间为 [createdAt(v), createdAt(v+1))（按 ingestTime）；
 * 升级后受理的事件不得出现在旧版本窗口的应纳入集合，旧窗口升级后保持稳定。
 */
@SpringBootTest
class RuleVersionReconciliationTest {

    private static final Logger log = LoggerFactory.getLogger(RuleVersionReconciliationTest.class);
    private static final String RULE = "VER_RECON_TEST";

    @Autowired private IngestionService ingestionService;
    @Autowired private RuleService ruleService;
    @Autowired private ReconciliationService reconciliationService;
    @Autowired private RuleRepository ruleRepository;
    @Autowired private AlertRepository alertRepository;
    @Autowired private EventRepository eventRepository;
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
        ruleRepository.findByRuleCodeOrderByVersionDesc(RULE).forEach(ruleRepository::delete);
    }

    private RuleUpsertRequest rule(int threshold) {
        return new RuleUpsertRequest(RULE, "版本归属测试规则",
                Map.of("action", "DENY"), "sourceIp", 60L, 3600L,
                threshold, RuleAction.ALERT.name(), 180L, true);
    }

    private EventIngestRequest deny(String id, Instant ts, String ip) {
        return new EventIngestRequest("FIREWALL", Map.of(
                "eventId", id, "timestamp", ts.toString(),
                "srcIp", ip, "action", "DENY", "target", "10.0.0.9:22"));
    }

    /**
     * 取一个"分钟内剩余时间足够容纳本用例全部事件偏移"的窗口起点（分钟对齐 + 5s）。
     * 当前分钟已过半时直接跳到下一分钟，避免事件时间跨桶造成偶发窗口分裂。
     */
    private Instant safeSlot() {
        Instant minute = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        Instant candidate = minute.plusSeconds(5);
        if (Instant.now().isAfter(minute.plusSeconds(35))) {
            candidate = minute.plusSeconds(65);
        }
        return candidate;
    }

    private WindowReconciliation oneWindow(Integer version, String groupKey) {
        return reconciliationService.reconcile(RULE, version, groupKey, null, null)
                .windows().stream().findFirst().orElseThrow();
    }

    @Test
    void eventsBelongOnlyToVersionEffectiveAtIngestTime() {
        ruleService.createOrUpdate(rule(3));
        RuleEntity v2 = null;

        Instant slot = safeSlot();
        // 1) 升级前：v1 生效，同窗口先受理 2 条（v1 阈值 3，不触发）
        ingestionService.ingest(deny("vr-pre-1", slot.plusSeconds(1), "10.1.0.1"));
        ingestionService.ingest(deny("vr-pre-2", slot.plusSeconds(2), "10.1.0.1"));
        // 2) 升级：阈值 3 -> 2，产生 v2
        v2 = ruleService.createOrUpdate(rule(2));
        log.info("[升级] v2.id={}, createdAt={}", v2.getId(), v2.getCreatedAt());
        // 3) 升级后：同一时间窗口内按 v2 再受理 2 条（v2 阈值 2，应触发）
        ingestionService.ingest(deny("vr-post-1", slot.plusSeconds(3), "10.1.0.1"));
        ingestionService.ingest(deny("vr-post-2", slot.plusSeconds(4), "10.1.0.1"));

        // --- 对账 v1：只包含升级前的 2 条，稳定、不触发、无告警 ---
        WindowReconciliation w1 = oneWindow(1, "10.1.0.1");
        log.info("[v1对账] stored={}, actual={}, expected={}, fired={}/shouldFire={}, missing={}, orphan={}",
                w1.storedCount(), w1.actualUniqueCount(), w1.expectedCount(),
                w1.fired(), w1.shouldFire(), w1.missingEventIds(), w1.orphanEventIds());
        assertEquals(2, w1.expectedCount(), "旧版本窗口的应纳入集合只能含升级前受理的事件");
        assertEquals(2, w1.actualUniqueCount());
        assertEquals(2, w1.storedCount());
        assertEquals(List.of("vr-pre-1", "vr-pre-2"),
                w1.contributions().stream().map(c -> c.eventId()).sorted().toList());
        assertTrue(w1.missingEventIds().isEmpty(), "升级后受理的事件不能被当成旧窗口 missing");
        assertTrue(w1.orphanEventIds().isEmpty());
        assertEquals(false, w1.shouldFire(), "旧版本窗口未达阈值，不应触发");
        assertNull(w1.matchedAlertId());
        assertTrue(w1.consistent());

        // --- 对账 v2：只包含升级后的 2 条，达阈值且已触发 ---
        WindowReconciliation w2 = oneWindow(2, "10.1.0.1");
        log.info("[v2对账] stored={}, actual={}, expected={}, fired={}/shouldFire={}, missing={}, orphan={}",
                w2.storedCount(), w2.actualUniqueCount(), w2.expectedCount(),
                w2.fired(), w2.shouldFire(), w2.missingEventIds(), w2.orphanEventIds());
        assertEquals(2, w2.expectedCount(), "新版本窗口只能含升级后受理的事件");
        assertEquals(List.of("vr-post-1", "vr-post-2"),
                w2.contributions().stream().map(c -> c.eventId()).sorted().toList());
        assertTrue(w2.missingEventIds().isEmpty(), "升级前事件不能被当成新窗口 missing");
        assertTrue(w2.orphanEventIds().isEmpty());
        assertTrue(w2.shouldFire());
        assertTrue(w2.fired());
        assertTrue(w2.matchedAlertId() != null);
        assertTrue(w2.consistent());

        long alertsBefore = alertRepository.count();
        // --- 自愈：所有窗口本就健康，0 变更，绝不抬高旧窗口或补建误报告警 ---
        RepairResult repair = reconciliationService.repair(
                new WindowRepairRequest(RULE, null, "10.1.0.1", null, null, true, "升级后全量收敛"),
                "ops-vr", "ADMIN");
        log.info("[自愈1] scanned={}, changed={}", repair.scannedWindows(), repair.changedWindows());
        assertEquals(0, repair.changedWindows(), "健康的版本窗口自愈不得产生任何变更");
        assertEquals(alertsBefore, alertRepository.count(), "自愈不得新建告警");

        WindowReconciliation w1After = oneWindow(1, "10.1.0.1");
        assertEquals(2, w1After.storedCount(), "旧版本窗口统计不得被自愈抬高");
        assertEquals(false, w1After.fired());
        assertNull(w1After.matchedAlertId());

        // --- 重复自愈：继续幂等 ---
        RepairResult repair2 = reconciliationService.repair(
                new WindowRepairRequest(RULE, null, "10.1.0.1", null, null, true, "重复收敛"),
                "ops-vr", "ADMIN");
        assertEquals(0, repair2.changedWindows());
        assertEquals(alertsBefore, alertRepository.count(), "重复自愈不得重复建警/累计");
        assertTrue(oneWindow(1, "10.1.0.1").consistent());
        assertTrue(oneWindow(2, "10.1.0.1").consistent());
    }

    @Test
    void eventAcceptedExactlyAtUpgradeBoundaryBelongsToNewVersion() {
        ruleService.createOrUpdate(rule(5));
        Instant slot = safeSlot();
        ingestionService.ingest(deny("vr-bd-pre", slot.plusSeconds(1), "10.1.0.1"));
        RuleEntity v2 = ruleService.createOrUpdate(rule(2));

        // 边界事件：受理时刻恰好等于 v2 生效时刻（createdAt），按 [createdAt(v2), ...) 归属 v2
        ingestionService.ingest(deny("vr-bd-edge", slot.plusSeconds(2), "10.1.0.1"));
        EventEntity edge = eventRepository.findAll().stream()
                .filter(e -> e.getEventId().equals("vr-bd-edge")).findFirst().orElseThrow();
        edge.setIngestTime(v2.getCreatedAt());
        eventRepository.saveAndFlush(edge);

        WindowReconciliation w1 = oneWindow(1, "10.1.0.1");
        WindowReconciliation w2 = oneWindow(2, "10.1.0.1");
        log.info("[边界] v1.ids={}, v2.ids={}, edge.ingestTime == v2.createdAt == {}",
                w1.contributions().stream().map(c -> c.eventId()).sorted().toList(),
                w2.contributions().stream().map(c -> c.eventId()).sorted().toList(),
                v2.getCreatedAt());
        assertEquals(List.of("vr-bd-pre"),
                w1.contributions().stream().map(c -> c.eventId()).sorted().toList(),
                "恰好落在升级边界受理的事件归属新版本，旧窗口不含它");
        assertEquals(List.of("vr-bd-edge"),
                w2.contributions().stream().map(c -> c.eventId()).sorted().toList());
        assertTrue(w1.consistent());
        assertTrue(w2.consistent());
    }

    @Test
    void queryingUnknownVersionIsExplainableAndEmptyVersionIsNotAnError() {
        ruleService.createOrUpdate(rule(3));
        // 不存在的版本：明确报 RULE_NOT_FOUND 并列出可用版本
        PipelineException ex = assertThrows(PipelineException.class,
                () -> reconciliationService.reconcile(RULE, 99, null, null, null));
        log.info("[未知版本] reason={}, message={}", ex.getReason(), ex.getMessage());
        assertEquals(com.github.h3yow.securityeventpipelinejava.common.RejectReason.RULE_NOT_FOUND,
                ex.getReason());
        assertTrue(ex.getMessage().contains("v99"));
        assertTrue(ex.getMessage().contains("v1"));

        // 存在但没有任何窗口的版本（v2）：返回空窗口列表而不是报错
        ruleService.createOrUpdate(rule(2));
        WindowReconciliationReport empty =
                reconciliationService.reconcile(RULE, 2, null, null, null);
        log.info("[空版本窗口] totalWindows={}", empty.totalWindows());
        assertEquals(0, empty.totalWindows());
        assertEquals(0, empty.inconsistentWindows());

        // 完全不存在的规则编码：同样明确报错
        assertThrows(PipelineException.class,
                () -> reconciliationService.reconcile("NO_SUCH_RULE_CODE", null, null, null, null));
    }

    @Test
    void concurrentUpgradeAndBackfillDoNotCrossVersionsAndConcurrentRepairConverges() throws Exception {
        // v1 阈值 100（任何交叠划分下都不会触发），v2 阈值 2；同组同窗口
        ruleService.createOrUpdate(new RuleUpsertRequest(RULE, "版本归属测试规则",
                Map.of("action", "DENY"), "sourceIp", 60L, 3600L,
                100, RuleAction.ALERT.name(), 180L, true));
        Instant slot = safeSlot();
        ingestionService.ingest(deny("vr-cx-pre-1", slot.plusSeconds(1), "10.1.0.2"));
        ingestionService.ingest(deny("vr-cx-pre-2", slot.plusSeconds(2), "10.1.0.2"));

        // 交叠批 A（3 条）：与升级真正同时起跑；每条按它实际获取规则锁时生效的版本归属，
        // 因此 a 条落 v1、(3-a) 条落 v2 都是合法线性化，系统对任何划分都必须一致。
        int overlapN = 3;
        java.util.concurrent.ExecutorService pool =
                java.util.concurrent.Executors.newFixedThreadPool(overlapN + 1);
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch firstWaveDone = new java.util.concurrent.CountDownLatch(overlapN + 1);
        pool.submit(() -> {
            try {
                start.await();
                ruleService.createOrUpdate(rule(2));
            } catch (Exception e) {
                log.error("并发升级异常", e);
            } finally {
                firstWaveDone.countDown();
            }
        });
        for (int i = 1; i <= overlapN; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    ingestionService.ingest(deny(
                            "vr-cx-a-" + idx, slot.plusSeconds(2 + idx), "10.1.0.2"));
                } catch (Exception e) {
                    log.error("交叠补录异常", e);
                } finally {
                    firstWaveDone.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(firstWaveDone.await(60, java.util.concurrent.TimeUnit.SECONDS));
        pool.shutdown();

        // 确认升级已提交后，批 B（4 条）必然归属 v2，保证 v2 窗口存在且达到阈值 2
        assertTrue(ruleService.history(RULE).stream().anyMatch(r -> r.getVersion() == 2));
        int afterN = 4;
        for (int i = 1; i <= afterN; i++) {
            ingestionService.ingest(deny("vr-cx-b-" + i, slot.plusSeconds(10 + i), "10.1.0.2"));
        }

        // 线性化断言：升级前 2 条永远在 v1；交叠批 3 条按受理时刻各自归位、不重不漏；批 B 全在 v2
        WindowReconciliation w1 = oneWindow(1, "10.1.0.2");
        WindowReconciliation w2 = oneWindow(2, "10.1.0.2");
        long aInV1 = w1.contributions().stream()
                .filter(c -> c.eventId().startsWith("vr-cx-a-")).count();
        long aInV2 = w2.contributions().stream()
                .filter(c -> c.eventId().startsWith("vr-cx-a-")).count();
        log.info("[并发归属] 交叠批落 v1={}/v2={}; v1.actual={}, v2.actual={}",
                aInV1, aInV2, w1.actualUniqueCount(), w2.actualUniqueCount());
        assertEquals(overlapN, aInV1 + aInV2, "交叠批每条事件必须恰好归属一个版本，不重不漏");
        assertEquals(List.of("vr-cx-pre-1", "vr-cx-pre-2"),
                w1.contributions().stream().map(c -> c.eventId())
                        .filter(id -> id.startsWith("vr-cx-pre-")).sorted().toList(),
                "升级前事件必须留在 v1 窗口");
        assertEquals(afterN, w2.contributions().stream()
                .filter(c -> c.eventId().startsWith("vr-cx-b-")).count(),
                "升级确认后受理的事件必须全部归属 v2");
        assertTrue(w1.missingEventIds().isEmpty() && w1.orphanEventIds().isEmpty(),
                "v1 窗口不得串入其它版本事件：missing/orphan 均应为空");
        assertTrue(w2.missingEventIds().isEmpty() && w2.orphanEventIds().isEmpty(),
                "v2 窗口不得串入其它版本事件：missing/orphan 均应为空");
        assertTrue(w1.consistent(), "并发交叠后 v1 窗口对账应直接一致，无需修复");
        assertTrue(w2.consistent(), "并发交叠后 v2 窗口对账应直接一致，无需修复");
        assertEquals(2 + aInV1, w1.expectedCount());
        assertEquals(aInV2 + afterN, w2.expectedCount());
        assertEquals(false, w1.shouldFire(), "v1 阈值 100，任何划分下都不触发");
        assertEquals(false, w1.fired());
        assertNull(w1.matchedAlertId());
        assertTrue(w2.shouldFire(), "v2 阈值 2，批 B 后必然达到");
        assertTrue(w2.fired());
        assertTrue(w2.matchedAlertId() != null);
        long v2AlertId = w2.matchedAlertId();

        // 6 次并发自愈：本就一致 => 全部 0 变更，统计/触发/告警保持一致
        int repairN = 6;
        java.util.concurrent.ExecutorService repairPool =
                java.util.concurrent.Executors.newFixedThreadPool(repairN);
        java.util.concurrent.CountDownLatch rstart = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch rdone = new java.util.concurrent.CountDownLatch(repairN);
        for (int i = 0; i < repairN; i++) {
            repairPool.submit(() -> {
                try {
                    rstart.await();
                    reconciliationService.repair(
                            new WindowRepairRequest(RULE, null, "10.1.0.2", null, null,
                                    true, "并发交叠后收敛"),
                            "ops-cx", "ADMIN");
                } catch (Exception e) {
                    log.error("并发自愈异常", e);
                } finally {
                    rdone.countDown();
                }
            });
        }
        rstart.countDown();
        assertTrue(rdone.await(60, java.util.concurrent.TimeUnit.SECONDS));
        repairPool.shutdown();

        WindowReconciliation w1After = oneWindow(1, "10.1.0.2");
        WindowReconciliation w2After = oneWindow(2, "10.1.0.2");
        log.info("[并发自愈后] v1 count={}/fired={}/alert={}, v2 count={}/fired={}/alert={}",
                w1After.storedCount(), w1After.fired(), w1After.matchedAlertId(),
                w2After.storedCount(), w2After.fired(), w2After.matchedAlertId());
        assertTrue(w1After.consistent() && w2After.consistent());
        assertEquals(w1.expectedCount(), w1After.storedCount());
        assertEquals(w2.expectedCount(), w2After.storedCount());
        assertEquals(false, w1After.fired());
        assertNull(w1After.matchedAlertId());
        assertEquals(v2AlertId, w2After.matchedAlertId(), "告警不得被重复创建");
        long groupAlerts = alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals("10.1.0.2")
                        && a.getRuleCode().equals(RULE)).count();
        assertEquals(1, groupAlerts, "全过程只能产生一条 v2 告警");
        long changedRepairs = repairAuditRepository.findAll().stream()
                .filter(a -> a.getChangedWindows() > 0).count();
        assertEquals(0, changedRepairs, "健康窗口的并发自愈全部应为 0 变更");
    }
}
