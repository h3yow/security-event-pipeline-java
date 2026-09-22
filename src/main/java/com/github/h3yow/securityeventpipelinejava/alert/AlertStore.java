package com.github.h3yow.securityeventpipelinejava.alert;

import com.github.h3yow.securityeventpipelinejava.detection.WindowEvaluation;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * 告警落库助手：每次 upsert 在独立事务中执行，
 * 并发冲突（唯一约束 / 乐观锁）只回滚本次事务，由调用方换新事务重试。
 */
@Component
public class AlertStore {

    private final AlertRepository alertRepository;

    public AlertStore(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    /** 单事务内完成 查找→合并 或 创建。 */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Alert upsert(WindowEvaluation eval, String fingerprint, String snapshot) {
        Optional<Alert> existing = alertRepository.findByFingerprint(fingerprint);
        if (existing.isPresent()) {
            Alert alert = existing.get();
            alert.merge(snapshot, Instant.now());
            return alertRepository.saveAndFlush(alert);
        }
        Alert alert = new Alert(fingerprint, eval.ruleId(), eval.ruleVersion(),
                eval.groupKey(), snapshot, Instant.now());
        return alertRepository.saveAndFlush(alert);
    }
}
