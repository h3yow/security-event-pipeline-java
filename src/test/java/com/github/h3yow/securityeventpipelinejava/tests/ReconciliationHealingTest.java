package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.common.AlertStatus;
import com.github.h3yow.securityeventpipelinejava.domain.IngestResult;
import com.github.h3yow.securityeventpipelinejava.domain.healing.HealOutcome;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.ReconciliationQuery;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.WindowReconciliationResult;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowHealAuditEntity;
import com.github.h3yow.securityeventpipelinejava.exception.DuplicateEventException;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.AlertTransitionRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowHealAuditRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.service.AlertService;
import com.github.h3yow.securityeventpipelinejava.service.HealingService;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import com.github.h3yow.securityeventpipelinejava.service.JsonService;
import com.github.h3yow.securityeventpipelinejava.service.ReconciliationService;
import com.github.h3yow.securityeventpipelinejava.service.RuleService;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import com.github.h3yow.securityeventpipelinejava.web.HealRequest;
import com.github.h3yow.securityeventpipelinejava.web.RuleUpsertRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 窗口对账 + 自愈 + 并发补录/重放集成测试。
 * 日志打印 [输入事件] / [判定依据] / [最终状态]。
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ReconciliationHealingTest {

    private static final Logger log = LoggerFactory.getLogger(ReconciliationHealingTest.class);

    @Autowired private IngestionService ingestionService;
    @Autowired private ReconciliationService reconciliationService;
    @Autowired private HealingService healingService;
    @Autowired private RuleService ruleService;
    @Autowired private AlertService alertService;
    @Autowired private EventRepository eventRepository;
    @Autowired private AlertRepository alertRepository;
    @Autowired private AlertTransitionRepository transitionRepository;
    @Autowired private RejectedEventRepository rejectedEventRepository;
    @Autowired private WindowAggregateRepository windowAggregateRepository;
    @Autowired private WindowEventRepository windowEventRepository;
    @Autowired private JsonService jsonService;
    @Autowired private RuleRepository ruleRepository;
    @Autowired private WindowHealAuditRepository healAuditRepository;
    @Autowired private MockMvc mockMvc;

    /**
     * 测试使用文件库且规则跨运行持久化：每个测试类启动时先把规则重置为确定的 v1 状态，
     * 使阈值/版本断言与本地已运行过多少次无关。
     */
    @BeforeAll
    void resetRules() {
        ruleRepository.deleteAllInBatch();
    }

    @BeforeEach
    void clean() {
        alertRepository.deleteAllInBatch();
        windowAggregateRepository.deleteAllInBatch();
        windowEventRepository.deleteAllInBatch();
        healAuditRepository.deleteAllInBatch();
        transitionRepository.deleteAllInBatch();
        rejectedEventRepository.deleteAllInBatch();
        eventRepository.deleteAllInBatch();
        // 规则表为空：DataSeeder 只在启动时播种，这里手动重建确定版本
        if (ruleRepository.count() == 0) {
            ruleService.createOrUpdate(new RuleUpsertRequest(
                    "AUTH_BRUTE_FORCE", "认证暴力破解",
                    Map.of("action", "LOGIN_FAIL"),
                    "actor", 60L, 120L, 3, "ALERT", 180L, true));
        }
    }

    private static Instant aligned(int second) {
        return Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(second);
    }

    private EventIngestRequest auth(String eventId, Instant ts, String user, String result) {
        return new EventIngestRequest("AUTH", Map.of(
                "eventId", eventId,
                "timestamp", ts.toString(),
                "username", user,
                "result", result,
                "service", "ssh"));
    }

    private WindowAggregateEntity windowOf(String group) {
        // 固定查 AUTH_BRUTE_FORCE v1 行：版本升级测试会新增更高版本行，不影响其它用例定位
        long authV1RuleId = ruleService.history("AUTH_BRUTE_FORCE").stream()
                .filter(r -> r.getVersion() == 1).findFirst().orElseThrow().getId();
        return windowAggregateRepository.findAllByOrderByIdDesc().stream()
                .filter(w -> w.getRuleId() == authV1RuleId && w.getGroupKey().equals(group))
                .findFirst().orElseThrow();
    }

    private String windowKey(WindowAggregateEntity w) {
        return w.getRuleId() + "#v" + w.getVersion() + "#" + w.getGroupKey() + "#" + w.getWindowStart();
    }

    // ---------- 并发补录：同窗口几十条不同事件 ----------

    @Test
    void thirtyDistinctEventsConcurrentBackfillCountExactlyOnce() throws Exception {
        Instant ts = aligned(20);
        int n = 30;
        List<EventIngestRequest> reqs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            reqs.add(auth("bf-" + i, ts, "nina", "LOGIN_FAIL"));
        }
        log.info("[输入事件] {} 条不同事件（同规则/同分组/同窗口），16 线程并发补录", n);

        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        List<String> outcomes = java.util.Collections.synchronizedList(new ArrayList<>());
        for (EventIngestRequest r : reqs) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestResult res = ingestionService.ingest(r);
                    outcomes.add(res.accepted() ? "ACCEPTED" : "REJECTED");
                } catch (Exception e) {
                    outcomes.add("ERROR:" + e.getClass().getSimpleName());
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        long accepted = outcomes.stream().filter("ACCEPTED"::equals).count();
        WindowAggregateEntity win = windowOf("nina");
        long links = windowEventRepository.findByWindowKeyOrderByEventIdAsc(windowKey(win)).size();
        log.info("[最终状态] 成功受理={}/{}, storedCount={}, 去重关联数={}, fired={}, alertId={}, 告警总数={}",
                accepted, n, win.getCount(), links, win.isFired(), win.getMatchedAlertId(),
                alertRepository.count());
        assertEquals(n, accepted, "不同事件必须全部成功受理，实际 outcomes=" + outcomes);
        assertEquals(n, win.getCount(), "纳入的去重事件数必须与成功受理数一致");
        assertEquals(n, links, "window_event 关联数必须与成功受理数一致");
        assertTrue(win.isFired());
        assertEquals(1, alertRepository.count(), "阈值触发只建一条告警");
    }

    // ---------- 并发重复重试：相同事件只算一次 ----------

    @Test
    void concurrentDuplicateRetriesOfSameEventsCountedOnce() throws Exception {
        Instant ts = aligned(25);
        int distinct = 3, threadsPer = 8;
        List<EventIngestRequest> reqs = new ArrayList<>();
        for (int i = 0; i < distinct; i++) {
            reqs.add(auth("rep-" + i, ts, "oscar", "LOGIN_FAIL"));
        }
        log.info("[输入事件] {} 条事件，每条由 {} 个线程并发重试提交", distinct, threadsPer);

        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(distinct * threadsPer);
        List<String> outcomes = java.util.Collections.synchronizedList(new ArrayList<>());
        for (EventIngestRequest r : reqs) {
            for (int t = 0; t < threadsPer; t++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        IngestResult res = ingestionService.ingest(r);
                        outcomes.add(res.accepted() ? "ACCEPTED" : "REJECTED");
                    } catch (DuplicateEventException e) {
                        outcomes.add("DUPLICATE");
                    } catch (Exception e) {
                        outcomes.add("ERROR:" + e.getClass().getSimpleName());
                    } finally {
                        done.countDown();
                    }
                });
            }
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        long accepted = outcomes.stream().filter("ACCEPTED"::equals).count();
        long duplicates = outcomes.stream().filter("DUPLICATE"::equals).count();
        WindowAggregateEntity win = windowOf("oscar");
        log.info("[最终状态] accepted={}, duplicate={}, storedCount={}, 告警总数={}",
                accepted, duplicates, win.getCount(), alertRepository.count());
        assertEquals(distinct, accepted);
        assertEquals((long) distinct * (threadsPer - 1), duplicates);
        assertEquals(distinct, win.getCount(), "相同事件重试只能计一次");
        assertEquals(1, alertRepository.count());
    }

    // ---------- 对账：健康窗口准确、稳定、可解释 ----------

    @Test
    void reconciliationOfHealthyWindowIsConsistentAndExplainable() {
        Instant ts = aligned(30);
        for (int i = 1; i <= 3; i++) {
            log.info("[输入事件](顺序) {}", jsonService.write(auth("ok-" + i, ts.plusSeconds(i), "pam", "LOGIN_FAIL")));
            ingestionService.ingest(auth("ok-" + i, ts.plusSeconds(i), "pam", "LOGIN_FAIL"));
        }
        WindowReconciliationResult r = reconciliationService.reconcile(
                new ReconciliationQuery("AUTH_BRUTE_FORCE", null, "pam", null, null)).get(0);
        log.info("[判定依据] windowKey={}, storedCount={}, unique={}, diff={}, fired={}/shouldFire={}, 贡献事件={}",
                r.windowKey(), r.storedCount(), r.uniqueEventCount(), r.countDiff(),
                r.fired(), r.shouldFire(),
                r.contributions().stream().map(c -> c.eventId() + "@" + c.actor() + "/" + c.action()).toList());
        log.info("[最终状态] consistent={}, countConsistent={}, firingConsistent={}, alert={}, missing={}, unexpected={}",
                r.consistent(), r.countConsistent(), r.firingConsistent(), r.alert(),
                r.missingEventIds(), r.unexpectedEventIds());

        assertTrue(r.consistent());
        assertEquals(3, r.storedCount());
        assertEquals(3, r.uniqueEventCount());
        assertEquals(0, r.countDiff());
        assertTrue(r.fired() && r.shouldFire());
        assertEquals(3, r.contributions().size(), "每个事件的贡献摘要都要可查");
        assertTrue(r.missingEventIds().isEmpty() && r.unexpectedEventIds().isEmpty());
        assertNotNull(r.alert());
        assertEquals(1, r.version());
    }

    // ---------- 对账：差异不只给总数，精确到事件 ----------

    @Test
    void reconciliationPinpointsMissingAndUnexpectedEvents() {
        Instant ts = aligned(35);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("drift-" + i, ts.plusSeconds(i), "quinn", "LOGIN_FAIL"));
        }
        // 一条不匹配该规则的已受理事件（LOGIN_SUCCESS），稍后被错误地挂到窗口关联上
        IngestResult other = ingestionService.ingest(auth("drift-other", ts.plusSeconds(2), "quinn", "LOGIN_SUCCESS"));
        assertTrue(other.accepted());

        WindowAggregateEntity win = windowOf("quinn");
        // 人为漂移：删掉一条正确关联、塞进一条错误关联、计数改小、清除触发标志
        WindowEventEntity first = windowEventRepository
                .findByWindowKeyOrderByEventIdAsc(windowKey(win)).stream()
                .filter(l -> l.getEventId().equals("drift-1")).findFirst().orElseThrow();
        windowEventRepository.deleteById(first.getId());
        windowEventRepository.flush();
        windowEventRepository.save(new WindowEventEntity(win.getRuleId(), windowKey(win), "drift-other"));
        win.setCount(5L);
        win.setFired(false);
        win.setMatchedAlertId(null);
        windowAggregateRepository.save(win);
        log.info("[输入事件] 已人为制造漂移：缺失 drift-1、多挂 drift-other、count 被改成 5");

        WindowReconciliationResult r = reconciliationService.reconcile(
                new ReconciliationQuery("AUTH_BRUTE_FORCE", null, "quinn", null, null)).get(0);
        log.info("[判定依据] storedCount={}, unique={}, diff={}, missing={}, unexpected={}",
                r.storedCount(), r.uniqueEventCount(), r.countDiff(),
                r.missingEventIds(), r.unexpectedEventIds());
        assertFalse(r.consistent());
        assertFalse(r.countConsistent());
        assertEquals(List.of("drift-1"), r.missingEventIds());
        assertEquals(List.of("drift-other"), r.unexpectedEventIds());
        assertEquals(3, r.uniqueEventCount());
        assertEquals(5, r.storedCount());
        assertEquals(2, r.countDiff());
        assertFalse(r.fired());
        assertTrue(r.shouldFire());
    }

    // ---------- 自愈：幂等修复计数与触发 ----------

    @Test
    void healingConvergesCountAndIsIdempotent() {
        Instant ts = aligned(40);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("fix-" + i, ts.plusSeconds(i), "ruth", "LOGIN_FAIL"));
        }
        WindowAggregateEntity win = windowOf("ruth");
        Long originalAlertId = win.getMatchedAlertId();
        // 漂移：删关联 + 计数改成 1 + 清除触发
        WindowEventEntity link = windowEventRepository
                .findByWindowKeyOrderByEventIdAsc(windowKey(win)).get(0);
        windowEventRepository.deleteById(link.getId());
        windowEventRepository.flush();
        win.setCount(1L);
        win.setFired(false);
        win.setMatchedAlertId(null);
        windowAggregateRepository.save(win);
        log.info("[输入事件] 漂移制造完成，原 alertId={} 仍携带窗口键，准备自愈", originalAlertId);

        HealOutcome first = healingService.heal("ops-alice",
                new HealRequest("AUTH_BRUTE_FORCE", null, "ruth", null, null, "巡检发现计数漂移"));
        log.info("[判定依据] 第一次自愈: scanned={}, healed={}, windows={}",
                first.scannedWindows(), first.healedWindows(), first.windows());
        assertEquals(1, first.healedWindows());

        WindowAggregateEntity after = windowOf("ruth");
        long links = windowEventRepository.findByWindowKeyOrderByEventIdAsc(windowKey(after)).size();
        log.info("[最终状态] count={}, 关联数={}, fired={}, alertId={}, 告警总数={}",
                after.getCount(), links, after.isFired(), after.getMatchedAlertId(), alertRepository.count());
        assertEquals(3, after.getCount());
        assertEquals(3, links);
        assertTrue(after.isFired());
        assertEquals(originalAlertId, after.getMatchedAlertId(), "已有且仍适用的告警应被复用，不重复建警");
        assertEquals(1, alertRepository.count());

        // 第二次自愈：幂等，无任何变更
        HealOutcome second = healingService.heal("ops-alice",
                new HealRequest("AUTH_BRUTE_FORCE", null, "ruth", null, null, "再次确认"));
        log.info("[最终状态] 第二次自愈: healed={}, windows.changed={}",
                second.healedWindows(), second.windows().stream().anyMatch(w -> w.changed()));
        assertEquals(0, second.healedWindows());
        assertTrue(second.windows().get(0).addedEventIds().isEmpty());
        assertTrue(second.windows().get(0).removedEventIds().isEmpty());
        assertEquals(1, alertRepository.count(), "幂等：不重复建警");
        WindowAggregateEntity finalWin = windowOf("ruth");
        assertEquals(3, finalWin.getCount());
        assertEquals(originalAlertId, finalWin.getMatchedAlertId());

        // 审计：两次调用各一条，含操作者/原因/窗口明细
        List<WindowHealAuditEntity> audits = healingService.auditTrail();
        assertEquals(2, audits.size());
        log.info("[最终状态] 自愈审计: {}", audits.stream()
                .map(a -> a.getId() + ":" + a.getTriggeredBy() + "/" + a.getReason()
                        + "/healed=" + a.getHealedWindows()).toList());
        assertEquals("ops-alice", audits.get(0).getTriggeredBy());
        assertTrue(audits.get(0).getDetailsJson().contains(windowKey(after)));
    }

    // ---------- 自愈：达阈值缺告警时补建，再次触发不重复 ----------

    @Test
    void healingCreatesMissingAlertOnceWhenThresholdReached() {
        Instant ts = aligned(45);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("miss-" + i, ts.plusSeconds(i), "sam", "LOGIN_FAIL"));
        }
        WindowAggregateEntity win = windowOf("sam");
        Long alertId = win.getMatchedAlertId();
        // 彻底删除告警及其窗口关联行，制造“达阈值但无告警”
        alertRepository.deleteAllInBatch();
        transitionRepository.deleteAllInBatch();
        win.setFired(false);
        win.setMatchedAlertId(null);
        windowAggregateRepository.save(win);
        log.info("[输入事件] 已制造达阈值(count=3)但告警缺失的窗口");

        HealOutcome first = healingService.heal("ops-bob",
                new HealRequest(null, null, "sam", null, null, "补建丢失告警"));
        log.info("[判定依据] 第一次自愈: {}", first.windows());
        assertEquals(1, alertRepository.count());
        AlertEntity created = alertRepository.findAll().get(0);
        assertEquals(AlertStatus.OPEN.name(), created.getStatus());
        assertEquals(1, created.getOccurrenceCount(), "补建告警不得重复累计");
        assertEquals(windowKey(windowOf("sam")), created.getWindowKeys().get(0));

        HealOutcome second = healingService.heal("ops-bob", null);
        assertEquals(0, second.healedWindows(), "第二次自愈无变化");
        assertEquals(1, alertRepository.count(), "不重复建警");
        assertEquals(created.getId(), windowOf("sam").getMatchedAlertId());
    }

    // ---------- 自愈：未达阈值的误报被解除 ----------

    @Test
    void healingResolvesFalseAlertWhenBelowThreshold() {
        Instant ts = aligned(50);
        ingestionService.ingest(auth("low-1", ts.plusSeconds(1), "tina", "LOGIN_FAIL"));
        ingestionService.ingest(auth("low-2", ts.plusSeconds(2), "tina", "LOGIN_FAIL"));
        WindowAggregateEntity win = windowOf("tina");
        assertFalse(win.isFired());

        // 制造误报：计数虚高到 5、fired、挂一条 OPEN 告警
        String wk = windowKey(win);
        AlertEntity falseAlert = new AlertEntity();
        falseAlert.setRuleId(win.getRuleId());
        falseAlert.setRuleVersion(win.getVersion());
        falseAlert.setRuleCode("AUTH_BRUTE_FORCE");
        falseAlert.setRuleSnapshotJson("{}");
        falseAlert.setGroupKey("tina");
        falseAlert.setStatus(AlertStatus.OPEN.name());
        falseAlert.setOccurrenceCount(1);
        falseAlert.getWindowKeys().add(wk);
        Instant now = Instant.now();
        falseAlert.setFirstEventTime(ts);
        falseAlert.setLastEventTime(ts);
        falseAlert.setCreatedAt(now);
        falseAlert.setUpdatedAt(now);
        falseAlert = alertRepository.save(falseAlert);
        win.setCount(5L);
        win.setFired(true);
        win.setMatchedAlertId(falseAlert.getId());
        windowAggregateRepository.save(win);
        log.info("[输入事件] 已制造误报：实际仅 2 条事件(<阈值3)，却 count=5/fired/OPEN 告警 {}", falseAlert.getId());

        HealOutcome outcome = healingService.heal("ops-carol",
                new HealRequest(null, null, "tina", null, null, "解除误报"));
        log.info("[判定依据] 自愈结果: {}", outcome.windows());
        WindowAggregateEntity after = windowOf("tina");
        assertEquals(2, after.getCount());
        assertFalse(after.isFired(), "未达阈值不得误报");
        assertNull(after.getMatchedAlertId());
        assertEquals(AlertStatus.RESOLVED.name(),
                alertService.get(falseAlert.getId()).getStatus(), "失去支撑的误报告警自动 RESOLVED");
        long healingTransitions = transitionRepository.findAll().stream()
                .filter(t -> "HEALING".equals(t.getOperatorRole())).count();
        assertEquals(1, healingTransitions, "自愈解除告警留一条流转审计");
    }

    // ---------- 自愈：并发重复触发结果一致 ----------

    @Test
    void concurrentHealingProducesConsistentResult() throws Exception {
        Instant ts = aligned(55);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("par-" + i, ts.plusSeconds(i), "uma", "LOGIN_FAIL"));
        }
        WindowAggregateEntity win = windowOf("uma");
        WindowEventEntity link = windowEventRepository
                .findByWindowKeyOrderByEventIdAsc(windowKey(win)).get(0);
        windowEventRepository.deleteById(link.getId());
        windowEventRepository.flush();
        win.setCount(2L);
        win.setFired(false);
        win.setMatchedAlertId(null);
        windowAggregateRepository.save(win);
        log.info("[输入事件] 漂移制造完成，8 个线程并发发起自愈");

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        List<HealOutcome> outcomes = java.util.Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    outcomes.add(healingService.heal("ops-concurrent",
                            new HealRequest(null, null, "uma", null, null, "并发自愈")));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        WindowAggregateEntity after = windowOf("uma");
        long links = windowEventRepository.findByWindowKeyOrderByEventIdAsc(windowKey(after)).size();
        long healedRuns = outcomes.stream().filter(o -> o.healedWindows() > 0).count();
        log.info("[最终状态] count={}, 关联数={}, fired={}, alertId={}, 告警总数={}, 发生实际修复的自愈次数={}",
                after.getCount(), links, after.isFired(), after.getMatchedAlertId(),
                alertRepository.count(), healedRuns);
        assertEquals(3, after.getCount());
        assertEquals(3, links);
        assertTrue(after.isFired());
        assertEquals(1, alertRepository.count(), "并发自愈不得重复建警/重复累计");
        assertEquals(1, healedRuns, "多次并发执行中只有一次实际改数据，结果必须一致");
        assertEquals(threads, healingService.auditTrail().size(), "每次调用都留审计");
    }

    // ---------- 对账：规则版本过滤，历史版本可查 ----------

    @Test
    void reconciliationFiltersByRuleVersion() {
        Instant ts = aligned(5);
        ingestionService.ingest(auth("ver-1", ts, "vicky", "LOGIN_FAIL"));
        // 升级规则到 v2（阈值改为 5）
        ruleService.createOrUpdate(new RuleUpsertRequest(
                "AUTH_BRUTE_FORCE", "认证暴力破解",
                Map.of("action", "LOGIN_FAIL"),
                "actor", 60L, 120L, 5, "ALERT", 180L, true));
        log.info("[输入事件] 规则已升级 v2(阈值5)，再补 2 条事件（v2 窗口 count=2 不触发）");
        for (int i = 2; i <= 3; i++) {
            ingestionService.ingest(auth("ver-" + i, ts.plusSeconds(i), "vicky", "LOGIN_FAIL"));
        }

        List<WindowReconciliationResult> v1 = reconciliationService.reconcile(
                new ReconciliationQuery("AUTH_BRUTE_FORCE", 1, null, null, null));
        List<WindowReconciliationResult> v2 = reconciliationService.reconcile(
                new ReconciliationQuery("AUTH_BRUTE_FORCE", 2, null, null, null));
        log.info("[判定依据] v1 窗口数={}, v2 窗口数={}; v1(stored={},unique={},fired={}/should={}), v2(stored={},unique={},fired={}/should={},threshold={})",
                v1.size(), v2.size(),
                v1.get(0).storedCount(), v1.get(0).uniqueEventCount(), v1.get(0).fired(), v1.get(0).shouldFire(),
                v2.get(0).storedCount(), v2.get(0).uniqueEventCount(), v2.get(0).fired(), v2.get(0).shouldFire(),
                v2.get(0).threshold());
        assertEquals(1, v1.size());
        assertEquals(1, v2.size());
        assertEquals(1, v1.get(0).version());
        assertEquals(2, v2.get(0).version());
        assertEquals(5, v2.get(0).threshold(), "对账必须反映当时版本的阈值");
        // 版本切换语义：ver-1 在 v1 生效期受理 -> v1 窗口(count=1，不触发)；
        // ver-2/ver-3 在 v2 生效后受理 -> v2 窗口(count=2 < 阈值5，不触发)；
        // 复算不会让 ver-2/3 “穿越”进旧版本窗口
        assertEquals(1, v1.get(0).storedCount());
        assertEquals(1, v1.get(0).uniqueEventCount());
        assertFalse(v1.get(0).fired());
        assertTrue(v1.get(0).consistent());
        assertEquals(2, v2.get(0).uniqueEventCount());
        assertEquals(2, v2.get(0).storedCount());
        assertFalse(v2.get(0).fired());
        assertFalse(v2.get(0).shouldFire(), "2 < v2 阈值 5，不应触发");

        // 恢复：本用例是唯一升级规则的用例，结束后重建 v1，避免与其它用例产生执行顺序耦合
        ruleRepository.deleteAllInBatch();
        ruleService.createOrUpdate(new RuleUpsertRequest(
                "AUTH_BRUTE_FORCE", "认证暴力破解",
                Map.of("action", "LOGIN_FAIL"),
                "actor", 60L, 120L, 3, "ALERT", 180L, true));
    }

    // ---------- HTTP：对账 / 自愈 / 审计端点 ----------

    @Test
    void reconcileAndHealEndpointsWorkOverHttp() throws Exception {
        Instant ts = aligned(8);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("http-" + i, ts.plusSeconds(i), "walt", "LOGIN_FAIL"));
        }

        // 对账：按规则+分组过滤，返回稳定可解释结构
        log.info("[输入事件] GET /api/audit/windows/reconcile?ruleCode=AUTH_BRUTE_FORCE&groupKey=walt");
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/api/audit/windows/reconcile")
                        .param("ruleCode", "AUTH_BRUTE_FORCE")
                        .param("groupKey", "walt"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$[0].consistent").value(true))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$[0].uniqueEventCount").value(3))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$[0].contributions.length()").value(3))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$[0].alert.id").exists());

        // 自愈：幂等（健康窗口 healed=0），并写一条审计
        log.info("[判定依据] POST /api/audit/windows/heal 健康窗口应 healed=0");
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/audit/windows/heal")
                        .header("X-Operator", "ops-http")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"groupKey\":\"walt\",\"reason\":\"HTTP验证\"}"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.healedWindows").value(0))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.triggeredBy").value("ops-http"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.auditId").exists());

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/api/audit/windows/heals"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$[0].triggeredBy").value("ops-http"));
        log.info("[最终状态] 对账/自愈/审计三个 HTTP 端点验证通过");
    }
}
