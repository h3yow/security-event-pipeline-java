package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.Application;
import com.github.h3yow.securityeventpipelinejava.alert.Alert;
import com.github.h3yow.securityeventpipelinejava.alert.AlertService;
import com.github.h3yow.securityeventpipelinejava.alert.AlertStatus;
import com.github.h3yow.securityeventpipelinejava.ingest.IngestResult;
import com.github.h3yow.securityeventpipelinejava.ingest.IngestService;
import com.github.h3yow.securityeventpipelinejava.ingest.RawLogRequest;
import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 重启持久化：服务重启后，未完成的告警状态、审计历史与聚合结果
 * 不丢失、不回退、不重复累计；幂等去重仍然生效。
 */
class RestartPersistenceTest {

    private static final Logger log = LoggerFactory.getLogger(RestartPersistenceTest.class);

    private static final long BASE_EPOCH =
            (Instant.parse("2026-09-22T12:00:00Z").getEpochSecond() / 300) * 300 + 60;

    @TempDir
    Path tempDir;

    private ConfigurableApplicationContext boot() {
        // 命令行参数优先级高于测试类路径下的 application.properties，确保指向临时文件库
        return new SpringApplicationBuilder(Application.class)
                .web(WebApplicationType.NONE)
                .run("--spring.datasource.url=jdbc:h2:file:" + tempDir.resolve("pipeline"),
                        "--spring.jpa.hibernate.ddl-auto=update",
                        "--spring.main.banner-mode=off");
    }

    private static RawLogRequest loginFail(String eventId, long offset) {
        Instant ts = Instant.ofEpochSecond(BASE_EPOCH + offset);
        return new RawLogRequest(EventSource.AUTH, eventId,
                "ts=" + ts + " action=LOGIN_FAIL src_ip=10.40.0.1 user=grace");
    }

    @Test
    void stateSurvivesRestartWithoutLossOrDoubleCounting() {
        // ---- 第一次启动：触发告警并认领 ----
        try (ConfigurableApplicationContext ctx = boot()) {
            log.info("[boot1] datasource url={}", ctx.getEnvironment().getProperty("spring.datasource.url"));
            IngestService ingest = ctx.getBean(IngestService.class);
            for (int i = 0; i < 3; i++) {
                IngestResult r = ingest.ingest(loginFail("rs-" + i, i * 10));
                log.info("[boot1] ingest rs-{} -> accepted={}", i, r.accepted());
            }
            AlertService alertService = ctx.getBean(AlertService.class);
            Alert alert = ctx.getBean(AlertRepository.class).findAll().get(0);
            alertService.transition(alert.getId(), AlertStatus.ACKNOWLEDGED, "ANALYST", "before restart");
            log.info("[boot1] alert id={} status={} hitCount={}",
                    alert.getId(), alert.getStatus(), alert.getHitCount());
        }

        // ---- 第二次启动（同一数据库文件）：状态不回退、不重复累计 ----
        log.info("db files in tempDir: {}", java.util.Arrays.toString(tempDir.toFile().list()));
        try (ConfigurableApplicationContext ctx = boot()) {
            log.info("[boot2] datasource url={}", ctx.getEnvironment().getProperty("spring.datasource.url"));
            AlertRepository alertRepository = ctx.getBean(AlertRepository.class);
            List<Alert> alerts = alertRepository.findAll();
            assertThat(alerts).hasSize(1);
            Alert alert = alerts.get(0);
            log.info("[boot2] after restart: alert id={} status={} hitCount={} snapshot={}",
                    alert.getId(), alert.getStatus(), alert.getHitCount(), alert.getEvaluationSnapshot());
            assertThat(alert.getStatus()).isEqualTo(AlertStatus.ACKNOWLEDGED); // 状态不回退
            assertThat(alert.getHitCount()).isEqualTo(1);

            // 重启后重复提交同一事件：仍被幂等拒绝，不重复计数
            IngestService ingest = ctx.getBean(IngestService.class);
            IngestResult dup = ingest.ingest(loginFail("rs-0", 0));
            log.info("[boot2] resubmit rs-0 -> accepted={} reason={}", dup.accepted(), dup.reason());
            assertThat(dup.accepted()).isFalse();
            assertThat(dup.reason()).isEqualTo(RejectionReason.DUPLICATE);

            // 新事件继续触发：在既有告警上合并累计，而非重新建警或清零
            IngestResult r = ingest.ingest(loginFail("rs-3", 15));
            assertThat(r.accepted()).isTrue();
            Alert merged = alertRepository.findAll().get(0);
            log.info("[boot2] after new trigger: hitCount={} status={}",
                    merged.getHitCount(), merged.getStatus());
            assertThat(alertRepository.findAll()).hasSize(1);
            // rs-3 触发两个锚点窗口（自身 + rs-2），合并累计 2 次：1 + 2 = 3，不重复建警、不从零重计
            assertThat(merged.getHitCount()).isEqualTo(3);
            assertThat(merged.getStatus()).isEqualTo(AlertStatus.ACKNOWLEDGED);
        }
    }
}
