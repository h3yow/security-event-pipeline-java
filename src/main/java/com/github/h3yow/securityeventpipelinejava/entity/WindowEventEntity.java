package com.github.h3yow.securityeventpipelinejava.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

/**
 * 窗口-事件关联（去重的权威依据）。(rule_id, window_key, event_id) 唯一：
 * 即使同一事件被重复处理路径触达，也不会被同一窗口重复计数。
 */
@Entity
@Table(name = "window_event",
        uniqueConstraints = @UniqueConstraint(name = "uk_window_event",
                columnNames = {"rule_id", "window_key", "event_id"}))
public class WindowEventEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_id", nullable = false)
    private long ruleId;

    /** WindowKey.encode()，含版本/分组/窗口起点。 */
    @Column(name = "window_key", nullable = false, length = 256)
    private String windowKey;

    @Column(name = "event_id", nullable = false, length = 128)
    private String eventId;

    public WindowEventEntity() {
    }

    public WindowEventEntity(long ruleId, String windowKey, String eventId) {
        this.ruleId = ruleId;
        this.windowKey = windowKey;
        this.eventId = eventId;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public long getRuleId() { return ruleId; }
    public void setRuleId(long ruleId) { this.ruleId = ruleId; }
    public String getWindowKey() { return windowKey; }
    public void setWindowKey(String windowKey) { this.windowKey = windowKey; }
    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
}
