package com.github.h3yow.securityeventpipelinejava.model;

import jakarta.persistence.*;
import java.time.Instant;

/** 归一化后的安全事件，落库持久化。eventId 全局唯一，保证幂等。 */
@Entity
@Table(name = "normalized_event", indexes = {
        @Index(name = "idx_event_group_time", columnList = "groupKey,eventTime")
})
public class NormalizedEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 来源系统提供的事件唯一标识，幂等键 */
    @Column(nullable = false, unique = true, length = 128)
    private String eventId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private EventSource source;

    /** 事件动作，如 LOGIN_FAIL / LOGIN_SUCCESS / CONNECTION_DENIED */
    @Column(nullable = false, length = 64)
    private String action;

    /** 事件时间（事件发生的真实时间，非到达时间） */
    @Column(nullable = false)
    private Instant eventTime;

    /** 服务端接收时间 */
    @Column(nullable = false)
    private Instant receivedAt;

    /** 关联分组键（默认源 IP），窗口聚合按此分组 */
    @Column(nullable = false, length = 128)
    private String groupKey;

    @Column(length = 128)
    private String username;

    @Column(length = 2000)
    private String rawPayload;

    protected NormalizedEvent() {}

    public NormalizedEvent(String eventId, EventSource source, String action, Instant eventTime,
                           Instant receivedAt, String groupKey, String username, String rawPayload) {
        this.eventId = eventId;
        this.source = source;
        this.action = action;
        this.eventTime = eventTime;
        this.receivedAt = receivedAt;
        this.groupKey = groupKey;
        this.username = username;
        this.rawPayload = rawPayload;
    }

    public Long getId() { return id; }
    public String getEventId() { return eventId; }
    public EventSource getSource() { return source; }
    public String getAction() { return action; }
    public Instant getEventTime() { return eventTime; }
    public Instant getReceivedAt() { return receivedAt; }
    public String getGroupKey() { return groupKey; }
    public String getUsername() { return username; }
    public String getRawPayload() { return rawPayload; }
}
