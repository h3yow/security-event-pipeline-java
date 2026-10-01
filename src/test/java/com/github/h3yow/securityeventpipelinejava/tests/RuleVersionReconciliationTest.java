package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.common.RuleAction;
import com.github.h3yow.securityeventpipelinejava.domain.recon.RepairResult;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliation;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliationReport;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.exception.PipelineException;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则升级（新版本）与窗口对账/自愈的归属测试：
 * 每个事件只能归属于其<b>受理时生效</b>的规则版本对应的窗口；升级前后在同一事件时间窗口内
 * 提交的事件不得互相串窗口；对账、自愈（含重复/并发）结果必须与该归属一致。
 */
@SpringBootTest
class RuleVersionReconciliationTest {

    private static final Logger log = LoggerFactory.getLogger(RuleVersionReconciliationTest.class);
    private static final String RULE = "RV_RECON_TEST";

    @Autowired private IngestionService ingestionService;
    @Autowired private RuleService ruleService;
    @Autowired private ReconciliationService reconciliationService;
    @Autowired private RuleRepository ruleRepository;
    @Autowired private EventRepository eventRepository;
    @Autowired private AlertRepository alertRepository;
    @Autowired private RejectedEventRepository rejectedEventRepository;
    @Autowired private WindowAggregateRepository windowAggregateRepository;
    @Autowired private WindowEventRepository windowEventRepository;

    @BeforeEach
    void clean() {
        // 先删规则行：否则遗留的新版本仍 enabled，会在后续清理过程中继续匹配受理事件建警
        ruleRepository.findByRuleCodeOrderByVersionDesc(RULE)
                .forEach(ruleRepository::delete);
        ruleRepository.flush();
        alertRepository.deleteAllInBatch();
        windowAggregateRepository.deleteAllInBatch();
        windowEventRepository.deleteAllInBatch();
        rejectedEventRepository.deleteAllInBatch();
        eventRepository.deleteAllInBatch();
    }

    /** 最后一个用例之后也要清理：文件数据库在测试类之间持久，遗留 enabled 规则会污染其它测试。 */
    @AfterEach
    void removeRule() {
        ruleRepository.findByRuleCodeOrderByVersionDesc(RULE)
                .forEach(ruleRepository::delete);
        ruleRepository.flush();
    }

    private EventIngestRequest auth(String id, Instant ts, String user) {
        return new EventIngestRequest("AUTH", Map.of(
                "eventId", id, "timestamp", ts.toString(),
                "username", user, "result", "LOGIN_FAIL", "service", "ssh"));
    }

    private RuleUpsertRequest rule(int threshold) {
        return new RuleUpsertRequest(RULE, "版本归属对账测试规则",
                Map.of("action", "LOGIN_FAIL"),
                "actor", 60L, 3600L, threshold, RuleAction.ALERT.name(), 180L, true);
    }

    private WindowAggregateEntity window(int version, String actor) {
        List<RuleEntity> rules = ruleRepository.findByRuleCodeOrderByVersionDesc(RULE);
        long ruleId = rules.stream().filter(r -> r.getVersion() == version)
                .findFirst().orElseThrow().getId();
        return windowAggregateRepository.findAll().stream()
                .filter(w -> w.getRuleId() == ruleId && w.getGroupKey().equals(actor))
                .findFirst().orElseThrow();
    }

    @Test
    void eventsAreAttributedToRuleVersionInEffectAtIngestTimeAcrossUpgrade() {
        // 0) v1 阈值 2
        ruleService.createOrUpdate(rule(2));
        Instant base = Instant.now().truncatedTo(ChronoUnit.MINUTES);

        // 1) 升级前：同一 60s 窗口内 amy 受理 2 条（v1 达到阈值，产生 1 条 v1 告警）
        ingestionService.ingest(auth("rv-a-1", base.plusSeconds(10), "amy"));
        ingestionService.ingest(auth("rv-a-2", base.plusSeconds(11), "amy"));
        // bob 升级前 2 条（v1 也触发）
        ingestionService.ingest(auth("rv-b-1", base.plusSeconds(12), "bob"));
        ingestionService.ingest(auth("rv-b-2", base.plusSeconds(13), "bob"));

        // 2) 升级：阈值 2 -> 3，产生 v2
        RuleEntity v2 = ruleService.createOrUpdate(rule(3));
        assertEquals(2, v2.getVersion());
        log.info("[规则升级] {} v2 已发布 id={}", RULE, v2.getId());

        // 3) 升级后：同一事件时间窗口内再受理（amy 1 条未达 v2 阈值；bob 3 条达到 v2 阈值）
        ingestionService.ingest(auth("rv-a-3", base.plusSeconds(20), "amy"));
        ingestionService.ingest(auth("rv-b-3", base.plusSeconds(21), "bob"));
        ingestionService.ingest(auth("rv-b-4", base.plusSeconds(22), "bob"));
        ingestionService.ingest(auth("rv-b-5", base.plusSeconds(23), "bob"));

        // ---- 实时链路落库的窗口归属本来就应正确 ----
        WindowAggregateEntity amyV1 = window(1, "amy");
        WindowAggregateEntity amyV2 = window(2, "amy");
        WindowAggregateEntity bobV1 = window(1, "bob");
        WindowAggregateEntity bobV2 = window(2, "bob");
        assertEquals(2, amyV1.getCount());
        assertEquals(1, amyV2.getCount());
        assertEquals(2, bobV1.getCount());
        assertEquals(3, bobV2.getCount());

        // ---- 对账：各版本窗口必须各自一致，升级前后事件不得互相串 ----
        WindowReconciliation amyV1r =
                reconciliationService.reconcile(RULE, 1, "amy", null, null).windows().get(0);
        WindowReconciliation amyV2r =
                reconciliationService.reconcile(RULE, 2, "amy", null, null).windows().get(0);
        log.info("[对账 amy v1] stored={}, actual={}, expected={}, missing={}, orphan={}, consistent={}",
                amyV1r.storedCount(), amyV1r.actualUniqueCount(), amyV1r.expectedCount(),
                amyV1r.missingEventIds(), amyV1r.orphanEventIds(), amyV1r.consistent());
        log.info("[对账 amy v2] stored={}, actual={}, expected={}, missing={}, orphan={}, consistent={}",
                amyV2r.storedCount(), amyV2r.actualUniqueCount(), amyV2r.expectedCount(),
                amyV2r.missingEventIds(), amyV2r.orphanEventIds(), amyV2r.consistent());

        assertTrue(amyV1r.consistent(), "旧版本窗口升级后必须保持原样：升级后事件不算 missing");
        assertEquals(2, amyV1r.expectedCount(), "v1 窗口只应包含升级前受理的 2 条");
        assertEquals(List.of(), amyV1r.missingEventIds());
        assertEquals(List.of(), amyV1r.orphanEventIds());
        assertTrue(amyV1r.fired());
        assertTrue(amyV1r.shouldFire());
        assertNotNull(amyV1r.matchedAlertId());

        assertTrue(amyV2r.consistent(), "新版本窗口只包含升级后受理的事件");
        assertEquals(1, amyV2r.expectedCount());
        assertFalse(amyV2r.shouldFire(), "v2 仅 1 条，未达阈值 3，不能误报");
        assertFalse(amyV2r.fired());
        assertNull(amyV2r.matchedAlertId());

        // 跨版本事件在贡献清单中要明确解释（而不是被当成 missing/orphan）
        Map<String, String> amyV1cats = amyV1r.contributions().stream()
                .collect(Collectors.toMap(c -> c.eventId(), c -> c.category()));
        assertEquals("COUNTED", amyV1cats.get("rv-a-1"));
        assertEquals("COUNTED", amyV1cats.get("rv-a-2"));
        assertEquals("EXCLUDED_OTHER_VERSION", amyV1cats.get("rv-a-3"),
                "升级后受理的事件在旧版本窗口中必须被解释为归属其它版本，而非缺失");

        Map<String, String> amyV2cats = amyV2r.contributions().stream()
                .collect(Collectors.toMap(c -> c.eventId(), c -> c.category()));
        assertEquals("EXCLUDED_OTHER_VERSION", amyV2cats.get("rv-a-1"));
        assertEquals("EXCLUDED_OTHER_VERSION", amyV2cats.get("rv-a-2"));
        assertEquals("COUNTED", amyV2cats.get("rv-a-3"));

        WindowReconciliation bobV2r =
                reconciliationService.reconcile(RULE, 2, "bob", null, null).windows().get(0);
        assertTrue(bobV2r.consistent());
        assertEquals(3, bobV2r.expectedCount());
        assertTrue(bobV2r.shouldFire());
        assertNotNull(bobV2r.matchedAlertId());

        // 全版本对账：4 个窗口全部一致
        WindowReconciliationReport all = reconciliationService.reconcile(RULE, null, null, null, null);
        assertEquals(4, all.totalWindows());
        assertEquals(0, all.inconsistentWindows(),
                "升级前后各版本窗口互不串扰，全部一致: " + all.windows().stream()
                        .filter(w -> !w.consistent())
                        .map(w -> w.ruleVersion() + "/" + w.groupKey() + w.missingEventIds() + w.orphanEventIds())
                        .toList());

        // ---- 自愈：在本来就正确的系统上空跑必须 0 变更、0 误建告警 ----
        long alertsBefore = alertRepository.count();
        RepairResult r1 = reconciliationService.repair(
                new WindowRepairRequest(RULE, null, null, null, null, true, "升级后全量对账自愈"),
                "ops-ver", "ADMIN");
        RepairResult r2 = reconciliationService.repair(
                new WindowRepairRequest(RULE, null, null, null, null, true, "重复自愈验证幂等"),
                "ops-ver", "ADMIN");
        log.info("[自愈] 第一次 changed={}, 第二次 changed={}, 告警数 {} -> {}",
                r1.changedWindows(), r2.changedWindows(), alertsBefore, alertRepository.count());
        assertEquals(0, r1.changedWindows(), "健康窗口自愈不得改动任何统计/告警");
        assertEquals(0, r2.changedWindows(), "重复自愈必须幂等");
        assertEquals(alertsBefore, alertRepository.count(), "不得新建任何告警（含 v2 amy 的误报）");

        // amy 在本规则下只有 1 条 v1 告警；bob v1/v2 各 1 条（不同 ruleId 不跨版本合并）
        List<AlertEntity> amyAlerts = alertRepository.findAll().stream()
                .filter(a -> a.getRuleCode().equals(RULE))
                .filter(a -> a.getGroupKey().equals("amy")).toList();
        assertEquals(1, amyAlerts.size(), "amy 只有 v1 的 1 条告警，v2 未达阈值不能误报");
        assertEquals(1, amyAlerts.get(0).getRuleVersion());
        assertEquals(1, amyAlerts.get(0).getOccurrenceCount(), "已存在告警不得被重复累计");
        List<String> amyAlertWindows = amyAlerts.get(0).getWindowKeys();
        assertTrue(amyAlertWindows.contains(amyV1.getRuleId() + "#v1#amy#" + amyV1.getWindowStart()));
        assertFalse(amyAlertWindows.contains(amyV2.getRuleId() + "#v2#amy#" + amyV2.getWindowStart()));

        // 最终再对账：各版本统计/触发/告警关联全部稳定一致
        WindowReconciliationReport finalReport =
                reconciliationService.reconcile(RULE, null, null, null, null);
        assertEquals(0, finalReport.inconsistentWindows());
    }

    @Test
    void queryingUnknownVersionGivesExplainable404AndHistoryStaysViewable() {
        ruleService.createOrUpdate(rule(2));
        Instant base = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        ingestionService.ingest(auth("rv-old-1", base.plusSeconds(30), "zoe"));
        ruleService.createOrUpdate(rule(3));

        // 不存在的版本：明确的 RULE_NOT_FOUND，而不是返回空或自相矛盾
        PipelineException ex = assertThrows(PipelineException.class, () ->
                reconciliationService.reconcile(RULE, 99, null, null, null));
        log.info("[未知版本] reason={}, message={}", ex.getReason(), ex.getMessage());
        assertEquals("RULE_NOT_FOUND", ex.getReason().name());

        // 已落库的旧版本窗口升级后仍可正常查看
        WindowReconciliation old =
                reconciliationService.reconcile(RULE, 1, "zoe", null, null).windows().get(0);
        log.info("[历史窗口] v1 zoe stored={}, expected={}, consistent={}",
                old.storedCount(), old.expectedCount(), old.consistent());
        assertEquals(1, old.expectedCount());
        assertEquals(1, old.storedCount());
        assertFalse(old.shouldFire());
        assertTrue(old.consistent());
    }

    @Test
    void concurrentBackfillInterleavedWithUpgradeAttributesEachEventExactlyOnce() throws Exception {
        // v1 阈值 50（保证并发受理期间不会建警干扰断言）
        ruleService.createOrUpdate(rule(50));
        Instant base = Instant.now().truncatedTo(ChronoUnit.MINUTES);

        // 30 个不同事件 + 1 次规则升级同时起跑（同一 60s 窗口、同一分组），再补 30 个
        int n = 30;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(2 * n + 1);
        List<String> errors = java.util.Collections.synchronizedList(new ArrayList<>());

        for (int i = 1; i <= n; i++) {
            int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    ingestionService.ingest(auth("rv-c-pre-" + idx, base.plusSeconds(10), "cyc"));
                } catch (Exception e) {
                    errors.add("pre-" + idx + ":" + e.getClass().getSimpleName());
                } finally {
                    done.countDown();
                }
            });
        }
        pool.submit(() -> {
            try {
                start.await();
                RuleEntity v2 = ruleService.createOrUpdate(rule(50));
                log.info("[并发交叠] 升级完成 v2 id={}, createdAt={}", v2.getId(), v2.getCreatedAt());
            } catch (Exception e) {
                errors.add("upgrade:" + e.getClass().getSimpleName());
            } finally {
                done.countDown();
            }
        });
        for (int i = 1; i <= n; i++) {
            int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    ingestionService.ingest(auth("rv-c-post-" + idx, base.plusSeconds(50), "cyc"));
                } catch (Exception e) {
                    errors.add("post-" + idx + ":" + e.getClass().getSimpleName());
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS),
                "并发受理与升级必须全部结束: " + errors);
        pool.shutdown();

        RuleEntity v1 = ruleRepository.findByRuleCodeOrderByVersionDesc(RULE).stream()
                .filter(r -> r.getVersion() == 1).findFirst().orElseThrow();
        RuleEntity v2 = ruleRepository.findByRuleCodeOrderByVersionDesc(RULE).stream()
                .filter(r -> r.getVersion() == 2).findFirst().orElseThrow();

        // 以受理时刻划分真实归属
        long preCount = eventRepository.findAll().stream()
                .filter(e -> e.getEventId().startsWith("rv-c-pre-"))
                .filter(e -> !e.getIngestTime().isBefore(v1.getCreatedAt())
                        && e.getIngestTime().isBefore(v2.getCreatedAt())).count();
        long postCount = eventRepository.findAll().stream()
                .filter(e -> e.getEventId().startsWith("rv-c-post-"))
                .filter(e -> !e.getIngestTime().isBefore(v2.getCreatedAt())).count();
        long totalAccepted = eventRepository.findAll().stream()
                .filter(e -> e.getEventId().startsWith("rv-c-")).count();
        log.info("[并发交叠] 受理总数={}, v1 生效期受理={}, v2 生效期受理={}, 错误={}",
                totalAccepted, preCount, postCount, errors);

        assertEquals(0, errors.size(), "并发交叠不应出现异常: " + errors);
        assertEquals(2L * n, totalAccepted, "每个不同事件只受理一次（不重）");
        assertEquals(2L * n, preCount + postCount, "每个事件恰好归属一个版本（不漏）");
        // 升级严格先于全部"post"事件、严格晚于全部"pre"事件（读视图串行化 + 单调生效时刻）
        assertEquals(n, preCount, "升级前批次全部在 v1 生效期受理");
        assertEquals(n, postCount, "升级后批次全部在 v2 生效期受理");

        // 对账：两个版本窗口各自一致、计数与归属完全吻合
        WindowReconciliation w1 =
                reconciliationService.reconcile(RULE, 1, "cyc", null, null).windows().get(0);
        WindowReconciliation w2 =
                reconciliationService.reconcile(RULE, 2, "cyc", null, null).windows().get(0);
        log.info("[并发交叠对账] v1 expected={}, stored={}, consistent={}; v2 expected={}, stored={}, consistent={}",
                w1.expectedCount(), w1.storedCount(), w1.consistent(),
                w2.expectedCount(), w2.storedCount(), w2.consistent());
        assertEquals(n, w1.expectedCount());
        assertEquals(n, w2.expectedCount());
        assertEquals(n, w1.storedCount());
        assertEquals(n, w2.storedCount());
        assertTrue(w1.consistent());
        assertTrue(w2.consistent());
        assertEquals(0, reconciliationService.reconcile(RULE, null, null, null, null)
                .inconsistentWindows());

        // 并发 + 重复自愈多轮后，统计/触发/告警保持一致
        ExecutorService healPool = Executors.newFixedThreadPool(8);
        CountDownLatch healDone = new CountDownLatch(8);
        for (int i = 0; i < 8; i++) {
            healPool.submit(() -> {
                try {
                    reconciliationService.repair(
                            new WindowRepairRequest(RULE, null, "cyc", null, null, true,
                                    "并发交叠后并发自愈"), "ops-cyc", "ADMIN");
                } finally {
                    healDone.countDown();
                }
            });
        }
        assertTrue(healDone.await(60, TimeUnit.SECONDS));
        healPool.shutdown();
        assertEquals(0, reconciliationService.reconcile(RULE, null, "cyc", null, null)
                .inconsistentWindows(), "8 次并发自愈后各版本窗口仍一致");
        assertEquals(n, window(1, "cyc").getCount());
        assertEquals(n, window(2, "cyc").getCount());
        // 两版本都未达阈值 50，不应为本规则 cyc 分组创建任何告警
        assertEquals(0, alertRepository.findAll().stream()
                .filter(a -> a.getRuleCode().equals(RULE))
                .filter(a -> a.getGroupKey().equals("cyc")).count(),
                "未达阈值不能误报，并发自愈也不得建警");
    }

    @Test
    void eventIngestedExactlyAtUpgradeBoundaryIsAttributedUnambiguouslyAndExplainably() {
        RuleEntity v1 = ruleService.createOrUpdate(rule(5));
        RuleEntity v2 = ruleService.createOrUpdate(rule(5));
        Instant boundary = v2.getCreatedAt();
        Instant base = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        log.info("[边界] v1 生效 {} -> v2 生效 {}（半开区间 [from,to)）",
                v1.getCreatedAt(), boundary);

        // 直接落库构造"受理时刻恰好等于 v2.createdAt"的已受理事件（正常链路中升级锁会放行到升级后）
        EventEntity boundaryEvent = new EventEntity();
        boundaryEvent.setEventId("rv-exact-boundary");
        boundaryEvent.setSource("AUTH");
        boundaryEvent.setEventTime(base.plusSeconds(5));
        boundaryEvent.setIngestTime(boundary);
        boundaryEvent.setActor("finn");
        boundaryEvent.setAction("LOGIN_FAIL");
        boundaryEvent.setTarget("ssh");
        boundaryEvent.setAttributesJson("{}");
        boundaryEvent.setRawPayload("{}");
        eventRepository.saveAndFlush(boundaryEvent);
        // 再构造一条受理时刻比边界早 1 微秒的事件，归属 v1
        EventEntity justBefore = new EventEntity();
        justBefore.setEventId("rv-just-before");
        justBefore.setSource("AUTH");
        justBefore.setEventTime(base.plusSeconds(6));
        justBefore.setIngestTime(boundary.minusNanos(1_000));
        justBefore.setActor("finn");
        justBefore.setAction("LOGIN_FAIL");
        justBefore.setTarget("ssh");
        justBefore.setAttributesJson("{}");
        justBefore.setRawPayload("{}");
        eventRepository.saveAndFlush(justBefore);

        // 已落库的历史窗口（v1 已有 1 条正确关联；v2 窗口存在但空，模拟升级后边界事件尚未补录）
        long windowStart = base.getEpochSecond();
        WindowAggregateEntity a1 = new WindowAggregateEntity();
        a1.setRuleId(v1.getId());
        a1.setVersion(1);
        a1.setGroupKey("finn");
        a1.setWindowStart(windowStart);
        a1.setWindowEnd(windowStart + 60);
        a1.setCount(1);
        a1.setThreshold(5);
        a1.setFired(false);
        windowAggregateRepository.saveAndFlush(a1);
        windowEventRepository.saveAndFlush(new WindowEventEntity(
                v1.getId(), v1.getId() + "#v1#finn#" + windowStart, "rv-just-before"));
        WindowAggregateEntity a2 = new WindowAggregateEntity();
        a2.setRuleId(v2.getId());
        a2.setVersion(2);
        a2.setGroupKey("finn");
        a2.setWindowStart(windowStart);
        a2.setWindowEnd(windowStart + 60);
        a2.setCount(0);
        a2.setThreshold(5);
        a2.setFired(false);
        windowAggregateRepository.saveAndFlush(a2);

        // 边界事件（ingestTime == v2.createdAt）必须确定归属 v2，不是 v1
        WindowReconciliation w1 =
                reconciliationService.reconcile(RULE, 1, "finn", null, null).windows().get(0);
        WindowReconciliation w2 =
                reconciliationService.reconcile(RULE, 2, "finn", null, null).windows().get(0);
        log.info("[边界对账] v1 expected={}, stored={}, consistent={}, 贡献={}",
                w1.expectedCount(), w1.storedCount(), w1.consistent(),
                w1.contributions().stream().map(c -> c.eventId() + ":" + c.category()).toList());
        log.info("[边界对账] v2 expected={}, stored={}, consistent={}, 贡献={}",
                w2.expectedCount(), w2.storedCount(), w2.consistent(),
                w2.contributions().stream().map(c -> c.eventId() + ":" + c.category()).toList());

        // v1 窗口已正确包含边界前事件；边界事件只在 v2 窗口缺失，两边互不串
        assertEquals(1, w1.expectedCount(), "早 1 微秒受理的事件归属 v1");
        assertEquals(List.of(), w1.missingEventIds());
        assertEquals(List.of(), w1.orphanEventIds());
        assertTrue(w1.consistent(), "v1 旧窗口在升级后保持原样");
        assertEquals(List.of("rv-exact-boundary"), w2.missingEventIds(),
                "恰好边界受理的事件确定归属 v2");
        assertEquals(1, w1.contributions().stream()
                .filter(c -> c.eventId().equals("rv-exact-boundary")
                        && c.category().equals("EXCLUDED_OTHER_VERSION")).count(),
                "边界事件在 v1 窗口给出明确的归属解释，而非自相矛盾的缺失");
        assertEquals(1, w2.contributions().stream()
                .filter(c -> c.eventId().equals("rv-just-before")
                        && c.category().equals("EXCLUDED_OTHER_VERSION")).count(),
                "边界前事件在 v2 窗口同样给出归属解释");

        // 自愈后：归属关联各自补齐，统计与归属一致、无任何误报告警（阈值 5 未达到）
        reconciliationService.repair(
                new WindowRepairRequest(RULE, null, "finn", null, null, true, "边界归属修复"),
                "ops-boundary", "ADMIN");
        WindowReconciliationReport all =
                reconciliationService.reconcile(RULE, null, "finn", null, null);
        log.info("[边界自愈后] 不一致窗口={}", all.inconsistentWindows());
        assertEquals(0, all.inconsistentWindows(), "自愈后两个版本窗口均与归属一致");
        assertEquals(1, window(1, "finn").getCount());
        assertEquals(1, window(2, "finn").getCount());
        assertEquals(0, alertRepository.findAll().stream()
                .filter(a -> a.getRuleCode().equals(RULE))
                .filter(a -> a.getGroupKey().equals("finn")).count(),
                "均未达阈值，不得产生告警");
    }
}
