package com.github.h3yow.securityeventpipelinejava.model;

import jakarta.persistence.*;
import java.time.Instant;

/** 被拒绝的原始记录，持久化以便审计与重放，绝不静默丢弃。 */
@Entity
@Table(name = "rejected_event")
public class RejectedEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 128)
    private String eventId;

    @Column(length = 64)
    private String sourceHint;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private RejectionReason reason;

    @Column(length = 500)
    private String detail;

    @Column(length = 2000)
    private String rawPayload;

    @Column(nullable = false)
    private Instant rejectedAt;

    protected RejectedEvent() {}

    public RejectedEvent(String eventId, String sourceHint, RejectionReason reason,
                         String detail, String rawPayload, Instant rejectedAt) {
        this.eventId = eventId;
        this.sourceHint = sourceHint;
        this.reason = reason;
        this.detail = detail;
        this.rawPayload = rawPayload;
        this.rejectedAt = rejectedAt;
    }

    public Long getId() { return id; }
    public String getEventId() { return eventId; }
    public String getSourceHint() { return sourceHint; }
    public RejectionReason getReason() { return reason; }
    public String getDetail() { return detail; }
    public String getRawPayload() { return rawPayload; }
    public Instant getRejectedAt() { return rejectedAt; }
}
