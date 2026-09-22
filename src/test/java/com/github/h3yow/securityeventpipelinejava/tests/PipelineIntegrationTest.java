package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.common.AlertStatus;
import com.github.h3yow.securityeventpipelinejava.common.OperatorRole;
import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.domain.IngestResult;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.exception.AccessDeniedException;
import com.github.h3yow.securityeventpipelinejava.exception.AlertStateException;
import com.github.h3yow.securityeventpipelinejava.exception.DuplicateEventException;
import com.github.h3yow.securityeventpipelinejava.exception.ValidationException;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.service.AlertService;
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 流水线集成测试。
 * 覆盖：并发重复提交、乱序/迟到事件、非法与越权状态流转、去重合并。
 * 日志打印输入事件、判定依据与最终状态。
 */
@SpringBootTest
class PipelineIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(PipelineIntegrationTest.class);

    @Autowired private IngestionService ingestionService;
    @Autowired private RuleService ruleService;
    @Autowired private AlertService alertService;
    @Autowired private EventRepository eventRepository;
    @Autowired private AlertRepository alertRepository;
    @Autowired private RejectedEventRepository rejectedEventRepository;
    @Autowired private WindowAggregateRepository windowAggregateRepository;
    @Autowired private WindowEventRepository windowEventRepository;
    @Autowired private JsonService jsonService;

    @BeforeEach
    void clean() throws Exception {
        // 顺序：先清依赖方，再清事件；规则保留（种子数据）
        alertRepository.deleteAllInBatch();
        windowAggregateRepository.deleteAllInBatch();
        windowEventRepository.deleteAllInBatch();
        rejectedEventRepository.deleteAllInBatch();
        eventRepository.deleteAllInBatch();
    }

    /** 对齐到当前分钟窗口内的固定秒点，避免 now() 相对时间跨越窗口边界导致计数分裂。 */
    private static Instant aligned(int second) {
        return Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES).plusSeconds(second);
    }

    private EventIngestRequest auth(String eventId, Instant ts, String user, String result) {
        return new EventIngestRequest("AUTH", Map.of(
                "eventId", eventId,
                "timestamp", ts.toString(),
                "username", user,
                "result", result,
                "service", "ssh"));
    }

    private WindowAggregateEntity firstWindow() {
        return windowAggregateRepository.findAllByOrderByIdDesc().stream()
                .min(Comparator.comparingLong(WindowAggregateEntity::getId))
                .orElseThrow();
    }

    @Test
    void concurrentDuplicateSubmissionProcessedExactlyOnce() throws Exception {
        Instant base = Instant.now().minusSeconds(5);
        EventIngestRequest req = auth("dup-evt-1", base, "alice", "LOGIN_FAIL");
        log.info("[输入事件] {} (将被 16 个线程并发提交)", jsonService.write(req));

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        List<String> outcomes = java.util.Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestResult r = ingestionService.ingest(req);
                    outcomes.add(r.accepted() ? "ACCEPTED" : "REJECTED:" + r.rejection().reason());
                } catch (DuplicateEventException e) {
                    outcomes.add("DUPLICATE_EXCEPTION:" + e.getReason());
                } catch (Exception e) {
                    outcomes.add("ERROR:" + e.getClass().getSimpleName());
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        long accepted = outcomes.stream().filter("ACCEPTED"::equals).count();
        long duplicates = outcomes.stream().filter(o -> o.contains("DUPLICATE")).count();
        log.info("[判定依据] 结果分布: accepted={}, duplicate={}, 全部结果={}", accepted, duplicates, outcomes);
        log.info("[最终状态] accepted_event 存在数={}, 窗口计数={}",
                eventRepository.existsByEventId("dup-evt-1"),
                windowAggregateRepository.findAllByOrderByIdDesc());

        assertEquals(1, accepted, "同一事件只能被处理一次");
        assertEquals(threads - 1, duplicates, "其余并发请求必须被判为重复");
        assertTrue(eventRepository.existsByEventId("dup-evt-1"));
    }

    @Test
    void outOfOrderEventsProduceStableWindowCount() {
        // 固定在同一 60s 窗口内的三个事件，故意乱序提交：3,1,2
        EventIngestRequest e1 = auth("ooo-1", aligned(12), "bob", "LOGIN_FAIL");
        EventIngestRequest e2 = auth("ooo-2", aligned(15), "bob", "LOGIN_FAIL");
        EventIngestRequest e3 = auth("ooo-3", aligned(18), "bob", "LOGIN_FAIL");

        Stream.of(e3, e1, e2).forEach(r -> {
            log.info("[输入事件](乱序) {}", jsonService.write(r));
            IngestResult result = ingestionService.ingest(r);
            log.info("[判定依据] accepted={}, alerts={}", result.accepted(), result.alertIds());
        });

        WindowAggregateEntity window = firstWindow();
        log.info("[最终状态] 窗口 count={}, threshold={}, fired={}, alertId={}",
                window.getCount(), window.getThreshold(), window.isFired(), window.getMatchedAlertId());
        assertEquals(3, window.getCount(), "乱序不得遗漏或重复计数");
        assertTrue(window.isFired());
        assertEquals(1, alertRepository.findAll().size(), "阈值命中只产生一条告警");
    }

    @Test
    void lateEventBeyondAllowedLatenessIsRejectedWithReason() {
        // 事件时间在 200 秒前：其窗口结束至少在 140 秒前，已超过 120 秒迟到宽限
        Instant lateTs = Instant.now().minusSeconds(200);
        EventIngestRequest req = auth("late-evt-1", lateTs, "carol", "LOGIN_FAIL");
        log.info("[输入事件](迟到) {} eventTime 距现在 200s，窗口结束距今>140s > 宽限120s", jsonService.write(req));

        IngestResult result = ingestionService.ingest(req);
        log.info("[判定依据] accepted={}, reason={}, message={}",
                result.accepted(), result.rejection() == null ? null : result.rejection().reason(),
                result.rejection() == null ? null : result.rejection().message());
        log.info("[最终状态] rejected_event 表记录数={}", rejectedEventRepository.count());

        assertFalse(result.accepted());
        assertEquals(RejectReason.WINDOW_EXPIRED.name(), result.rejection().reason());
        assertFalse(eventRepository.existsByEventId("late-evt-1"), "迟到拒绝的事件不得落库");
        assertEquals(1, rejectedEventRepository.count(), "拒绝必须留痕，不静默丢弃");
    }

    @Test
    void illegalAndUnauthorizedStateTransitionsAreRejected() {
        Instant base = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES);
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("sm-" + i, base.plusSeconds(10 + i), "dave", "LOGIN_FAIL"));
        }
        AlertEntity alert = alertRepository.findAll().get(0);
        long id = alert.getId();
        log.info("[初始状态] 告警 {} status={}", id, alert.getStatus());

        // RESOLVED 是终态：先合法 ACK -> RESOLVED，再尝试回退
        alertService.transition(id, AlertStatus.ACKNOWLEDGED.name(), "analyst-1",
                OperatorRole.ANALYST, "开始处置");
        AlertEntity resolved = alertService.transition(id, AlertStatus.RESOLVED.name(), "analyst-1",
                OperatorRole.ANALYST, "处置完成");
        log.info("[最终状态] 告警 {} status={}", id, resolved.getStatus());
        assertEquals(AlertStatus.RESOLVED.name(), resolved.getStatus());

        AlertStateException illegal = assertThrows(AlertStateException.class,
                () -> alertService.transition(id, AlertStatus.OPEN.name(), "admin",
                        OperatorRole.ADMIN, "试图回退终态"));
        log.info("[判定依据] 非法流转被拒绝 reason={}, message={}",
                illegal.getReason(), illegal.getMessage());
        assertEquals(RejectReason.ILLEGAL_STATE_TRANSITION, illegal.getReason());

        // 新建一条 OPEN 告警用于越权校验
        for (int i = 1; i <= 3; i++) {
            ingestionService.ingest(auth("sm2-" + i, base.plusSeconds(30 + i), "erin", "LOGIN_FAIL"));
        }
        AlertEntity alert2 = alertRepository.findAll().stream()
                .filter(a -> a.getStatus().equals(AlertStatus.OPEN.name())).findFirst().orElseThrow();

        AccessDeniedException denied = assertThrows(AccessDeniedException.class,
                () -> alertService.transition(alert2.getId(), AlertStatus.RESOLVED.name(),
                        "viewer-1", OperatorRole.VIEWER, "viewer 试图解决告警"));
        log.info("[判定依据] 越权被拒绝 reason={}, message={}", denied.getReason(), denied.getMessage());
        assertEquals(RejectReason.ACCESS_DENIED, denied.getReason());
        assertEquals(AlertStatus.OPEN.name(), alertService.get(alert2.getId()).getStatus(),
                "越权操作不得改变状态");

        // ANALYST 不允许直接 SUPPRESS
        AccessDeniedException denied2 = assertThrows(AccessDeniedException.class,
                () -> alertService.transition(alert2.getId(), AlertStatus.SUPPRESSED.name(),
                        "analyst-2", OperatorRole.ANALYST, "试图抑制"));
        assertEquals(RejectReason.ACCESS_DENIED, denied2.getReason());
    }

    @Test
    void repeatedWindowFiringsMergeIntoOneAlert() throws InterruptedException {
        // 两个相邻完整窗口（上一分钟/当前分钟）各达到阈值，间隔在 dedupSeconds(180s) 内 => 合并
        Instant w1 = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES).minusSeconds(60);
        Instant w2 = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES);
        for (int i = 0; i < 3; i++) {
            ingestionService.ingest(auth("merge-w1-" + i, w1.plusSeconds(10 + i), "frank", "LOGIN_FAIL"));
        }
        log.info("[判定依据] 第一个窗口已命中");
        for (int i = 0; i < 3; i++) {
            ingestionService.ingest(auth("merge-w2-" + i, w2.plusSeconds(30 + i), "frank", "LOGIN_FAIL"));
        }
        List<AlertEntity> alerts = alertRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals("frank")).toList();
        log.info("[最终状态] frank 的告警数={}, occurrenceCount={}, windows={}",
                alerts.size(),
                alerts.stream().findFirst().map(AlertEntity::getOccurrenceCount).orElse(-1L),
                alerts.stream().findFirst().map(AlertEntity::getWindowKeys).orElse(List.of()));
        assertEquals(1, alerts.size(), "dedup 间隔内的再次命中必须合并");
        assertEquals(2, alerts.get(0).getOccurrenceCount());
        assertEquals(2, alerts.get(0).getWindowKeys().size());
    }
}
