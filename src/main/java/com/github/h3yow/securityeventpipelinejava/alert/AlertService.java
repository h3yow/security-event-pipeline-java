package com.github.h3yow.securityeventpipelinejava.alert;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.h3yow.securityeventpipelinejava.detection.WindowEvaluation;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertTransitionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

/** 告警生命周期服务：去重合并、抑制、状态机流转（含角色鉴权与审计）。 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private static final String ROLE_ANALYST = "ANALYST";
    private static final String ROLE_ADMIN = "ADMIN";

    /** 状态机：from -> (to -> 允许的角色) */
    private static final Map<AlertStatus, Map<AlertStatus, Set<String>>> TRANSITIONS = Map.of(
            AlertStatus.OPEN, Map.of(
                    AlertStatus.ACKNOWLEDGED, Set.of(ROLE_ANALYST, ROLE_ADMIN),
                    AlertStatus.SUPPRESSED, Set.of(ROLE_ADMIN),
                    AlertStatus.FALSE_POSITIVE, Set.of(ROLE_ANALYST, ROLE_ADMIN)),
            AlertStatus.ACKNOWLEDGED, Map.of(
                    AlertStatus.INVESTIGATING, Set.of(ROLE_ANALYST, ROLE_ADMIN),
                    AlertStatus.SUPPRESSED, Set.of(ROLE_ADMIN)),
            AlertStatus.INVESTIGATING, Map.of(
                    AlertStatus.RESOLVED, Set.of(ROLE_ANALYST, ROLE_ADMIN),
                    AlertStatus.FALSE_POSITIVE, Set.of(ROLE_ANALYST, ROLE_ADMIN),
                    AlertStatus.SUPPRESSED, Set.of(ROLE_ADMIN)));

    private final AlertRepository alertRepository;
    private final AlertTransitionRepository transitionRepository;
    private final AlertStore alertStore;

    public AlertService(AlertRepository alertRepository,
                        AlertTransitionRepository transitionRepository,
                        AlertStore alertStore) {
        this.alertRepository = alertRepository;
        this.transitionRepository = transitionRepository;
        this.alertStore = alertStore;
    }

    /**
     * 根据窗口评估结果创建或合并告警。
     * 去重指纹 = ruleId + groupKey + 窗口桶（事件时间对齐到窗口宽度的桶），
     * 同一指纹的重复触发合并为一条告警并累计 hitCount，判定依据快照同步更新。
     * 并发冲突（唯一约束 / 乐观锁）在独立事务中重试，保证不丢不重。
     */
    public Alert raiseOrMerge(WindowEvaluation evaluation) {
        String fingerprint = fingerprint(evaluation);
        String snapshot = snapshot(evaluation);
        for (int attempt = 1; ; attempt++) {
            try {
                Alert alert = alertStore.upsert(evaluation, fingerprint, snapshot);
                log.info("alert upserted: id={} fingerprint={} hitCount={} status={} attempt={}",
                        alert.getId(), fingerprint, alert.getHitCount(), alert.getStatus(), attempt);
                return alert;
            } catch (DataIntegrityViolationException | ObjectOptimisticLockingFailureException e) {
                if (attempt >= 20) {
                    throw e;
                }
                log.debug("alert upsert conflict (attempt {}), retrying: {}", attempt, e.getMessage());
                backoff(attempt);
            }
        }
    }

    /**
     * 状态流转。非法流转或越权角色将被拒绝并说明原因；每次成功流转写入审计记录。
     */
    @Transactional
    public Alert transition(long alertId, AlertStatus target, String role, String note) {
        Alert alert = alertRepository.findById(alertId).orElseThrow(() ->
                new AlertTransitionException(AlertTransitionException.Kind.ALERT_NOT_FOUND,
                        "alert not found: " + alertId));
        AlertStatus from = alert.getStatus();
        Map<AlertStatus, Set<String>> allowed = TRANSITIONS.getOrDefault(from, Map.of());
        if (!allowed.containsKey(target)) {
            throw new AlertTransitionException(AlertTransitionException.Kind.ILLEGAL_TRANSITION,
                    "transition " + from + " -> " + target + " is not allowed"
                            + (allowed.isEmpty() ? " (terminal state)" : "; allowed: " + allowed.keySet()));
        }
        if (role == null || !allowed.get(target).contains(role)) {
            throw new AlertTransitionException(AlertTransitionException.Kind.FORBIDDEN_ROLE,
                    "role " + role + " may not perform " + from + " -> " + target
                            + "; required: " + allowed.get(target));
        }
        try {
            alert.transitionTo(target, Instant.now());
            Alert saved = alertRepository.saveAndFlush(alert);
            transitionRepository.save(new AlertTransition(alertId, from, target, role,
                    note, Instant.now()));
            log.info("alert transition: id={} {} -> {} by role={} note={}",
                    alertId, from, target, role, note);
            return saved;
        } catch (ObjectOptimisticLockingFailureException e) {
            throw new AlertTransitionException(AlertTransitionException.Kind.ILLEGAL_TRANSITION,
                    "concurrent modification on alert " + alertId + ", please retry");
        }
    }

    /** 冲突重试退避：随次数增加的随机抖动，降低并发碰撞概率。 */
    private static void backoff(int attempt) {
        try {
            Thread.sleep((long) (Math.random() * 10L * attempt));
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    /** 去重指纹：ruleId|groupKey|窗口桶号（事件时间 / 窗口宽度）。 */
    static String fingerprint(WindowEvaluation eval) {
        long width = Duration.between(eval.windowStart(), eval.windowEnd()).getSeconds();
        long bucket = width > 0 ? eval.windowEnd().getEpochSecond() / width : 0;
        return eval.ruleId() + "|" + eval.groupKey() + "|" + bucket;
    }

    private static String snapshot(WindowEvaluation eval) {
        try {
            return MAPPER.writeValueAsString(eval);
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialize evaluation", e);
        }
    }
}
