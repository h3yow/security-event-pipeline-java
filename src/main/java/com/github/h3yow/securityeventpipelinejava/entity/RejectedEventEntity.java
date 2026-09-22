package com.github.h3yow.securityeventpipelinejava.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;

/** 被拒绝的记录审计表：字段缺失/格式非法/时间戳异常等不静默丢弃，全部留痕。 */
@Entity
@Table(name = "rejected_event")
public class RejectedEventEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", length = 128)
    private String eventId;

    @Column(length = 32)
    private String source;

    /** 可区分的失败原因枚举名，见 RejectReason。 */
    @Column(nullable = false, length = 48)
    private String reason;

    @Column(length = 512)
    private String detail;

    @Lob
    @Column(name = "raw_payload")
    private String rawPayload;

    @Column(name = "rejected_at", nullable = false)
    private Instant rejectedAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
    public String getRawPayload() { return rawPayload; }
    public void setRawPayload(String rawPayload) { this.rawPayload = rawPayload; }
    public Instant getRejectedAt() { return rejectedAt; }
    public void setRejectedAt(Instant rejectedAt) { this.rejectedAt = rejectedAt; }
}
