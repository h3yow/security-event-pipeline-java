package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.domain.IngestResult;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.exception.DuplicateEventException;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import com.github.h3yow.securityeventpipelinejava.service.JsonService;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 同一规则、同一分组、同一时间窗口内：几十条<b>不同</b>事件并发补录/重放。
 * 只要事件被成功受理，窗口最终去重事件数必须与成功受理数完全一致。
 */
@SpringBootTest
class ConcurrentBackfillTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentBackfillTest.class);

    @Autowired private IngestionService ingestionService;
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
    void fiftyDistinctEventsInSameWindowSubmittedConcurrentlyAreAllCounted() throws Exception {
        // 同一窗口（当前分钟内固定秒点），同一分组 nora，50 条不同事件
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(20);
        int n = 50;
        List<EventIngestRequest> requests = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            requests.add(auth("backfill-nora-" + i, ts, "nora"));
        }
        log.info("[输入事件] 同一窗口 {} 内 {} 条不同事件，由 {} 个线程同时提交", ts, n, n);

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger errors = new AtomicInteger();
        List<String> errorDetails = Collections.synchronizedList(new ArrayList<>());

        for (EventIngestRequest req : requests) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestResult r = ingestionService.ingest(req);
                    if (r.accepted()) {
                        accepted.incrementAndGet();
                    } else {
                        errors.incrementAndGet();
                        errorDetails.add("REJECTED:" + r.rejection().reason());
                    }
                } catch (DuplicateEventException e) {
                    errors.incrementAndGet();
                    errorDetails.add("DUPLICATE:" + e.getReason());
                } catch (Exception e) {
                    errors.incrementAndGet();
                    errorDetails.add("ERROR:" + e.getClass().getSimpleName() + ":" + e.getMessage());
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS), "并发提交必须全部结束");
        pool.shutdown();

        WindowAggregateEntity window = windowAggregateRepository.findAll().stream()
                .filter(w -> w.getGroupKey().equals("nora")).findFirst().orElseThrow();
        long windowRows = windowEventRepository.findAll().stream()
                .filter(we -> we.getWindowKey().equals(window.getRuleId()
                        + "#v" + window.getVersion() + "#nora#" + window.getWindowStart())).count();

        log.info("[判定依据] 成功受理数={}, 窗口统计 count={}, window_event 去重行数={}, threshold={}, fired={}",
                accepted.get(), window.getCount(), windowRows, window.getThreshold(), window.isFired());
        log.info("[最终状态] 异常数={} {}, 关联告警ID={}, 告警数={}",
                errors.get(), errorDetails.stream().sorted().distinct().toList(),
                window.getMatchedAlertId(),
                alertRepository.findAll().stream().filter(a -> a.getGroupKey().equals("nora")).count());

        assertEquals(0, errors.get(), "并发补录不应出现失败: " + errorDetails.stream().sorted().distinct().toList());
        assertEquals(n, accepted.get(), "50 条不同事件必须全部成功受理");
        assertEquals(n, windowRows, "窗口去重事件数必须等于成功受理数");
        assertEquals(n, window.getCount(), "窗口统计值必须等于去重事件数，不能少算也不能重复算");
        assertTrue(window.isFired(), "50 >= 阈值 3，窗口必须已触发");
        assertEquals(1, alertRepository.findAll().stream().filter(a -> a.getGroupKey().equals("nora")).count(),
                "同窗口并发只应产生一条告警");
    }
}
