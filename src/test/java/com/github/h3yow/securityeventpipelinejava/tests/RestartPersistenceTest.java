package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.common.AlertStatus;
import com.github.h3yow.securityeventpipelinejava.common.OperatorRole;
import com.github.h3yow.securityeventpipelinejava.domain.IngestResult;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.exception.DuplicateEventException;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.service.AlertService;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 重启持久化测试：使用独立的 H2 文件库，顺序启动两个 Spring 上下文模拟服务重启，
 * 验证窗口计数、告警状态在重启后不丢失、不回退；重启后重复提交不会重复累计。
 */
class RestartPersistenceTest {

    private static final Logger log = LoggerFactory.getLogger(RestartPersistenceTest.class);
    private static final String DB_DIR = "build/restart-db";

    private EventIngestRequest auth(String id, Instant ts, String user) {
        return new EventIngestRequest("AUTH", Map.of(
                "eventId", id, "timestamp", ts.toString(),
                "username", user, "result", "LOGIN_FAIL", "service", "ssh"));
    }

    @Test
    void stateSurvivesRestartAndNoDoubleCounting() throws Exception {
        try (Stream<Path> files = Files.walk(Path.of(DB_DIR))) {
            files.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(java.io.File::delete);
        } catch (Exception ignored) {
        }

        Instant base = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES);
        long alertId;
        long windowCount;

        // ---- 第一次启动：3 个事件命中阈值，建警并 ACK ----
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(
                com.github.h3yow.securityeventpipelinejava.Application.class)
                .run(
                        "--spring.datasource.url=jdbc:h2:file:./" + DB_DIR + "/db;AUTO_SERVER=TRUE",
                        "--spring.jpa.hibernate.ddl-auto=update")) {
            IngestionService ingestion = ctx.getBean(IngestionService.class);
            AlertService alerts = ctx.getBean(AlertService.class);
            for (int i = 1; i <= 3; i++) {
                IngestResult r = ingestion.ingest(auth("restart-" + i, base.plusSeconds(10 + i), "grace"));
                log.info("[第一次启动] 输入 restart-{} => accepted={}, alerts={}", i, r.accepted(), r.alertIds());
            }
            AlertEntity alert = ctx.getBean(AlertRepository.class).findAll().stream()
                    .filter(a -> a.getGroupKey().equals("grace")).findFirst().orElseThrow();
            alertId = alert.getId();
            alerts.transition(alertId, AlertStatus.ACKNOWLEDGED.name(),
                    "analyst-x", OperatorRole.ANALYST, "重启前确认");
            windowCount = ctx.getBean(WindowAggregateRepository.class).findAll().stream()
                    .filter(w -> w.getGroupKey().equals("grace"))
                    .mapToLong(WindowAggregateEntity::getCount).findFirst().orElseThrow();
            log.info("[第一次启动最终状态] alertId={}, status=ACKNOWLEDGED, windowCount={}", alertId, windowCount);
        }

        // ---- 第二次启动：状态必须保留 ----
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(
                com.github.h3yow.securityeventpipelinejava.Application.class)
                .run(
                        "--spring.datasource.url=jdbc:h2:file:./" + DB_DIR + "/db;AUTO_SERVER=TRUE",
                        "--spring.jpa.hibernate.ddl-auto=update")) {
            AlertEntity reloaded = ctx.getBean(AlertRepository.class).findById(alertId).orElseThrow();
            log.info("[重启后状态] alertId={}, status={}, occurrenceCount={}",
                    reloaded.getId(), reloaded.getStatus(), reloaded.getOccurrenceCount());
            assertEquals(AlertStatus.ACKNOWLEDGED.name(), reloaded.getStatus(),
                    "重启后未完成的告警状态不得丢失或回退");

            long countAfterRestart = ctx.getBean(WindowAggregateRepository.class).findAll().stream()
                    .filter(w -> w.getGroupKey().equals("grace"))
                    .mapToLong(WindowAggregateEntity::getCount).findFirst().orElseThrow();
            assertEquals(windowCount, countAfterRestart, "重启后窗口计数不得回退或重复累计");

            // 重启后重复提交旧事件：必须被判重，计数不变
            assertThrows(DuplicateEventException.class,
                    () -> ctx.getBean(IngestionService.class)
                            .ingest(auth("restart-1", base.plusSeconds(11), "grace")));
            long countAfterDup = ctx.getBean(WindowAggregateRepository.class).findAll().stream()
                    .filter(w -> w.getGroupKey().equals("grace"))
                    .mapToLong(WindowAggregateEntity::getCount).findFirst().orElseThrow();
            log.info("[重启后重放重复事件] 计数保持={}, accepted_event exists={}",
                    countAfterDup, ctx.getBean(EventRepository.class).existsByEventId("restart-1"));
            assertEquals(windowCount, countAfterDup, "重放不得重复累计");

            // 新事件（同窗口内迟到）可以继续累计
            IngestResult r = ctx.getBean(IngestionService.class)
                    .ingest(auth("restart-4", base.plusSeconds(20), "grace"));
            long countNew = ctx.getBean(WindowAggregateRepository.class).findAll().stream()
                    .filter(w -> w.getGroupKey().equals("grace"))
                    .mapToLong(WindowAggregateEntity::getCount).findFirst().orElseThrow();
            log.info("[重启后新事件] accepted={}, alerts={}, 窗口计数 {} -> {}",
                    r.accepted(), r.alertIds(), countAfterDup, countNew);
            assertEquals(windowCount + 1, countNew, "重启后合法事件应能继续累计");
            // 已触发窗口不重复建警：关联到同一告警，grace 仍只有一条告警
            assertTrue(r.alertIds().contains(alertId), "已触发窗口的后续事件应关联原告警");
            long graceAlerts = ctx.getBean(AlertRepository.class).findAll().stream()
                    .filter(a -> a.getGroupKey().equals("grace")).count();
            assertEquals(1, graceAlerts, "不得因重启重复建警");
        }
    }
}
