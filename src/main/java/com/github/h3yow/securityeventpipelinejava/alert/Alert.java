package com.github.h3yow.securityeventpipelinejava.alert;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * 告警。fingerprint（ruleId+groupKey+窗口桶）唯一，用于去重合并；
 * 乐观锁保证并发状态流转安全；判定依据（评估快照）随告警持久化。
 */
@Entity
@Table(name = "alert", indexes = @Index(name = "idx_alert_fingerprint", columnList = "fingerprint", unique = true))
public class Alert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 200)
    private String fingerprint;

    @Column(nullable = false, length = 64)
    private String ruleId;

    @Column(nullable = false)
    private int ruleVersion;

    @Column(nullable = false, length = 128)
    private String groupKey;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AlertStatus status;

    /** 合并进入该告警的事件总数 */
    @Column(nullable = false)
    private long hitCount;

    /** 判定依据快照（JSON：窗口、计数、阈值、事件 id 列表） */
    @Column(nullable = false, length = 4000)
    private String evaluationSnapshot;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    @Version
    private long version;

    protected Alert() {}

    public Alert(String fingerprint, String ruleId, int ruleVersion, String groupKey,
                 String evaluationSnapshot, Instant now) {
        this.fingerprint = fingerprint;
        this.ruleId = ruleId;
        this.ruleVersion = ruleVersion;
        this.groupKey = groupKey;
        this.status = AlertStatus.OPEN;
        this.hitCount = 1;
        this.evaluationSnapshot = evaluationSnapshot;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public Long getId() { return id; }
    public String getFingerprint() { return fingerprint; }
    public String getRuleId() { return ruleId; }
    public int getRuleVersion() { return ruleVersion; }
    public String getGroupKey() { return groupKey; }
    public AlertStatus getStatus() { return status; }
    public long getHitCount() { return hitCount; }
    public String getEvaluationSnapshot() { return evaluationSnapshot; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public long getVersion() { return version; }

    /** 合并一次新的触发：累计计数并更新判定依据快照。 */
    public void merge(String newSnapshot, Instant now) {
        this.hitCount++;
        this.evaluationSnapshot = newSnapshot;
        this.updatedAt = now;
    }

    /** 状态流转（合法性由 AlertService 校验）。 */
    public void transitionTo(AlertStatus target, Instant now) {
        this.status = target;
        this.updatedAt = now;
    }
}
