package com.github.h3yow.securityeventpipelinejava.alert;

import jakarta.persistence.*;
import java.time.Instant;

/** 告警状态流转审计记录，持久化保证可追溯。 */
@Entity
@Table(name = "alert_transition")
public class AlertTransition {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long alertId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AlertStatus fromStatus;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AlertStatus toStatus;

    /** 操作者角色 */
    @Column(nullable = false, length = 32)
    private String actorRole;

    @Column(length = 500)
    private String note;

    @Column(nullable = false)
    private Instant occurredAt;

    protected AlertTransition() {}

    public AlertTransition(Long alertId, AlertStatus fromStatus, AlertStatus toStatus,
                           String actorRole, String note, Instant occurredAt) {
        this.alertId = alertId;
        this.fromStatus = fromStatus;
        this.toStatus = toStatus;
        this.actorRole = actorRole;
        this.note = note;
        this.occurredAt = occurredAt;
    }

    public Long getId() { return id; }
    public Long getAlertId() { return alertId; }
    public AlertStatus getFromStatus() { return fromStatus; }
    public AlertStatus getToStatus() { return toStatus; }
    public String getActorRole() { return actorRole; }
    public String getNote() { return note; }
    public Instant getOccurredAt() { return occurredAt; }
}
