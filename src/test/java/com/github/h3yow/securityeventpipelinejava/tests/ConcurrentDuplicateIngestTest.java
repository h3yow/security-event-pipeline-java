package com.github.h3yow.securityeventpipelinejava.tests;

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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** 并发重复提交：同一 eventId 在并发重试下只能被处理一次。 */
@SpringBootTest
class ConcurrentDuplicateIngestTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentDuplicateIngestTest.class);
    private static final int THREADS = 16;

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

    @Test
    void sameEventIdConcurrentlySubmittedIsProcessedOnce() throws Exception {
        RawLogRequest req = new RawLogRequest(EventSource.AUTH, "dup-1",
                "ts=2026-09-22T12:00:00Z action=LOGIN_FAIL src_ip=172.16.0.1 user=carol");
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<IngestResult> results = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < THREADS; i++) {
            futures.add(pool.submit((Callable<Void>) () -> {
                start.await();
                results.add(ingestService.ingest(req));
                return null;
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        long accepted = results.stream().filter(IngestResult::accepted).count();
        long duplicates = results.stream()
                .filter(r -> !r.accepted() && r.reason() == RejectionReason.DUPLICATE).count();
        log.info("input=eventId dup-1 x{} concurrent -> accepted={} duplicate={} persistedEvents={}",
                THREADS, accepted, duplicates, eventRepository.count());

        assertThat(accepted).isEqualTo(1);
        assertThat(duplicates).isEqualTo(THREADS - 1);
        assertThat(eventRepository.count()).isEqualTo(1);
    }

    @Test
    void concurrentDistinctEventsAllProcessedExactlyOnce() throws Exception {
        int n = 20;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<IngestResult> results = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String eventId = "c-" + i;
            // 同一事件提交两次（模拟重试），共 2n 次提交
            for (int retry = 0; retry < 2; retry++) {
                futures.add(pool.submit((Callable<Void>) () -> {
                    start.await();
                    results.add(ingestService.ingest(new RawLogRequest(EventSource.AUTH, eventId,
                            "ts=2026-09-22T12:10:00Z action=LOGIN_FAIL src_ip=172.16.1.1 user=dave")));
                    return null;
                }));
            }
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        long accepted = results.stream().filter(IngestResult::accepted).count();
        log.info("input={} distinct events x2 retries -> accepted={} persistedEvents={}",
                n, accepted, eventRepository.count());
        assertThat(accepted).isEqualTo(n);
        assertThat(eventRepository.count()).isEqualTo(n);
    }
}
