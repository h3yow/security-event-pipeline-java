package com.github.h3yow.securityeventpipelinejava.tests;

import com.github.h3yow.securityeventpipelinejava.alert.Alert;
import com.github.h3yow.securityeventpipelinejava.alert.AlertService;
import com.github.h3yow.securityeventpipelinejava.alert.AlertStatus;
import com.github.h3yow.securityeventpipelinejava.alert.AlertTransition;
import com.github.h3yow.securityeventpipelinejava.alert.AlertTransitionException;
import com.github.h3yow.securityeventpipelinejava.detection.WindowEvaluation;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertTransitionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 告警状态机：非法/越权流转被拒绝且原因可区分，合法流转留审计痕迹。 */
@SpringBootTest
class AlertStateMachineTest {

    private static final Logger log = LoggerFactory.getLogger(AlertStateMachineTest.class);

    @Autowired
    AlertService alertService;
    @Autowired
    AlertRepository alertRepository;
    @Autowired
    AlertTransitionRepository transitionRepository;

    @BeforeEach
    void clean() {
        transitionRepository.deleteAll();
        alertRepository.deleteAll();
    }

    private Alert newAlert() {
        WindowEvaluation eval = new WindowEvaluation("BRUTE_FORCE_LOGIN", 1, "10.20.0.1",
                Instant.parse("2026-09-22T12:00:00Z"), Instant.parse("2026-09-22T12:05:00Z"),
                3, 3, true, List.of("s-1", "s-2", "s-3"));
        Alert alert = alertService.raiseOrMerge(eval);
        log.info("raised alert: id={} status={} evaluation={}", alert.getId(), alert.getStatus(), eval);
        return alert;
    }

    private Alert transitionAndLog(long id, AlertStatus target, String role) {
        Alert a = alertService.transition(id, target, role, "test-note");
        log.info("transition: alertId={} -> {} by role={} accepted, finalStatus={}",
                id, target, role, a.getStatus());
        return a;
    }

    @Test
    void illegalTransitionsAreRejectedWithReason() {
        Alert alert = newAlert();
        // OPEN 不能直接 RESOLVED
        assertThatThrownBy(() -> alertService.transition(alert.getId(), AlertStatus.RESOLVED, "ADMIN", null))
                .isInstanceOfSatisfying(AlertTransitionException.class, e -> {
                    assertThat(e.getKind()).isEqualTo(AlertTransitionException.Kind.ILLEGAL_TRANSITION);
                    log.info("rejected: OPEN->RESOLVED reason={}", e.getMessage());
                });
        // OPEN 不能进入 INVESTIGATING（需先 ACK）
        assertThatThrownBy(() -> alertService.transition(alert.getId(), AlertStatus.INVESTIGATING, "ADMIN", null))
                .isInstanceOfSatisfying(AlertTransitionException.class, e ->
                        assertThat(e.getKind()).isEqualTo(AlertTransitionException.Kind.ILLEGAL_TRANSITION));
        // 状态未被改变
        assertThat(alertRepository.findById(alert.getId()).orElseThrow().getStatus())
                .isEqualTo(AlertStatus.OPEN);
    }

    @Test
    void forbiddenRoleIsRejectedWithReason() {
        Alert alert = newAlert();
        // SUPPRESSED 仅 ADMIN 可执行
        assertThatThrownBy(() -> alertService.transition(alert.getId(), AlertStatus.SUPPRESSED, "ANALYST", null))
                .isInstanceOfSatisfying(AlertTransitionException.class, e -> {
                    assertThat(e.getKind()).isEqualTo(AlertTransitionException.Kind.FORBIDDEN_ROLE);
                    log.info("rejected: ANALYST OPEN->SUPPRESSED reason={}", e.getMessage());
                });
        // 未知角色一律拒绝
        assertThatThrownBy(() -> alertService.transition(alert.getId(), AlertStatus.ACKNOWLEDGED, "GUEST", null))
                .isInstanceOfSatisfying(AlertTransitionException.class, e ->
                        assertThat(e.getKind()).isEqualTo(AlertTransitionException.Kind.FORBIDDEN_ROLE));
        assertThat(alertRepository.findById(alert.getId()).orElseThrow().getStatus())
                .isEqualTo(AlertStatus.OPEN);
    }

    @Test
    void terminalStateHasNoOutgoingTransitions() {
        Alert alert = newAlert();
        transitionAndLog(alert.getId(), AlertStatus.ACKNOWLEDGED, "ANALYST");
        transitionAndLog(alert.getId(), AlertStatus.INVESTIGATING, "ANALYST");
        transitionAndLog(alert.getId(), AlertStatus.RESOLVED, "ADMIN");
        // 终态不可再流转
        assertThatThrownBy(() -> alertService.transition(alert.getId(), AlertStatus.OPEN, "ADMIN", null))
                .isInstanceOfSatisfying(AlertTransitionException.class, e -> {
                    assertThat(e.getKind()).isEqualTo(AlertTransitionException.Kind.ILLEGAL_TRANSITION);
                    log.info("rejected: RESOLVED->OPEN reason={}", e.getMessage());
                });
    }

    @Test
    void missingAlertIsRejected() {
        assertThatThrownBy(() -> alertService.transition(999999L, AlertStatus.ACKNOWLEDGED, "ADMIN", null))
                .isInstanceOfSatisfying(AlertTransitionException.class, e -> {
                    assertThat(e.getKind()).isEqualTo(AlertTransitionException.Kind.ALERT_NOT_FOUND);
                    log.info("rejected: unknown alert reason={}", e.getMessage());
                });
    }

    @Test
    void legalPathIsAudited() {
        Alert alert = newAlert();
        transitionAndLog(alert.getId(), AlertStatus.ACKNOWLEDGED, "ANALYST");
        transitionAndLog(alert.getId(), AlertStatus.INVESTIGATING, "ANALYST");
        transitionAndLog(alert.getId(), AlertStatus.FALSE_POSITIVE, "ADMIN");

        List<AlertTransition> history = transitionRepository
                .findByAlertIdOrderByOccurredAtAsc(alert.getId());
        history.forEach(t -> log.info("audit: {} -> {} by {} note={}",
                t.getFromStatus(), t.getToStatus(), t.getActorRole(), t.getNote()));
        assertThat(history).hasSize(3);
        assertThat(history).extracting(AlertTransition::getToStatus)
                .containsExactly(AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING,
                        AlertStatus.FALSE_POSITIVE);
        assertThat(alertRepository.findById(alert.getId()).orElseThrow().getStatus())
                .isEqualTo(AlertStatus.FALSE_POSITIVE);
    }

    @Test
    void mergingIntoSuppressedAlertDoesNotReopen() {
        Alert alert = newAlert();
        transitionAndLog(alert.getId(), AlertStatus.SUPPRESSED, "ADMIN");
        // 同指纹再次触发：合并计数但状态保持 SUPPRESSED（抑制语义）
        WindowEvaluation eval = new WindowEvaluation("BRUTE_FORCE_LOGIN", 1, "10.20.0.1",
                Instant.parse("2026-09-22T12:00:00Z"), Instant.parse("2026-09-22T12:05:00Z"),
                4, 3, true, List.of("s-1", "s-2", "s-3", "s-4"));
        Alert merged = alertService.raiseOrMerge(eval);
        log.info("merged into suppressed alert: id={} hitCount={} finalStatus={}",
                merged.getId(), merged.getHitCount(), merged.getStatus());
        assertThat(merged.getId()).isEqualTo(alert.getId());
        assertThat(merged.getHitCount()).isEqualTo(2);
        assertThat(merged.getStatus()).isEqualTo(AlertStatus.SUPPRESSED);
    }
}
