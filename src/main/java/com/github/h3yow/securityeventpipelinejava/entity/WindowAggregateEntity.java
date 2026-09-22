package com.github.h3yow.securityeventpipelinejava.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

/**
 * 规则窗口聚合计数。唯一键 (rule_id, version, group_key, window_start)
 * 保证乱序/迟到事件与并发提交下，窗口计数既不重复也不遗漏（配合事件级唯一关联表）。
 */
@Entity
@Table(name = "window_aggregate",
        uniqueConstraints = @UniqueConstraint(name = "uk_window",
                columnNames = {"rule_id", "version", "group_key", "window_start"}))
public class WindowAggregateEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_id", nullable = false)
    private long ruleId;

    @Column(nullable = false)
    private int version;

    @Column(name = "group_key", nullable = false, length = 128)
    private String groupKey;

    @Column(name = "window_start", nullable = false)
    private long windowStart;

    @Column(name = "window_end", nullable = false)
    private long windowEnd;

    @Column(nullable = false)
    private long count;

    @Column(name = "threshold", nullable = false)
    private int threshold;

    @Column(nullable = false)
    private boolean fired;

    @Column(name = "matched_alert_id")
    private Long matchedAlertId;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public long getRuleId() { return ruleId; }
    public void setRuleId(long ruleId) { this.ruleId = ruleId; }
    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }
    public String getGroupKey() { return groupKey; }
    public void setGroupKey(String groupKey) { this.groupKey = groupKey; }
    public long getWindowStart() { return windowStart; }
    public void setWindowStart(long windowStart) { this.windowStart = windowStart; }
    public long getWindowEnd() { return windowEnd; }
    public void setWindowEnd(long windowEnd) { this.windowEnd = windowEnd; }
    public long getCount() { return count; }
    public void setCount(long count) { this.count = count; }
    public int getThreshold() { return threshold; }
    public void setThreshold(int threshold) { this.threshold = threshold; }
    public boolean isFired() { return fired; }
    public void setFired(boolean fired) { this.fired = fired; }
    public Long getMatchedAlertId() { return matchedAlertId; }
    public void setMatchedAlertId(Long matchedAlertId) { this.matchedAlertId = matchedAlertId; }
}
