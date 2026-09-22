package com.github.h3yow.securityeventpipelinejava.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

/** 已接受并归一化的事件。eventId 唯一，保证重复提交只会落库一次。 */
@Entity
@Table(name = "accepted_event", uniqueConstraints = @UniqueConstraint(name = "uk_event_id", columnNames = "event_id"))
public class EventEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", nullable = false, length = 128)
    private String eventId;

    @Column(nullable = false, length = 32)
    private String source;

    @Column(name = "event_time", nullable = false)
    private Instant eventTime;

    @Column(name = "ingest_time", nullable = false)
    private Instant ingestTime;

    @Column(length = 128)
    private String actor;

    @Column(length = 128)
    private String action;

    @Column(length = 256)
    private String target;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    /** 归一化后保留的扩展属性，JSON 字符串。 */
    @Lob
    @Column(name = "attributes_json")
    private String attributesJson;

    @Lob
    @Column(name = "raw_payload")
    private String rawPayload;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public Instant getEventTime() { return eventTime; }
    public void setEventTime(Instant eventTime) { this.eventTime = eventTime; }
    public Instant getIngestTime() { return ingestTime; }
    public void setIngestTime(Instant ingestTime) { this.ingestTime = ingestTime; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getAttributesJson() { return attributesJson; }
    public void setAttributesJson(String attributesJson) { this.attributesJson = attributesJson; }
    public String getRawPayload() { return rawPayload; }
    public void setRawPayload(String rawPayload) { this.rawPayload = rawPayload; }
}
