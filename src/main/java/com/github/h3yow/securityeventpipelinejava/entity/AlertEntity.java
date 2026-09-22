package com.github.h3yow.securityeventpipelinejava.entity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 告警：去重/合并的产物。同一规则同一分组在 dedupSeconds 内的多次窗口命中
 * 合并为一条告警（occurrenceCount 累加、关联窗口追加），状态持久化以保证重启不丢失/不回退。
 */
@Entity
@Table(name = "alert")
public class AlertEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_id", nullable = false)
    private long ruleId;

    /** 告警首次产生时命中的规则版本；ruleSnapshotJson 保存当时规则全文。 */
    @Column(name = "rule_version", nullable = false)
    private int ruleVersion;

    @Column(name = "rule_code", nullable = false, length = 64)
    private String ruleCode;

    @Lob
    @Column(name = "rule_snapshot_json", nullable = false)
    private String ruleSnapshotJson;

    @Column(name = "group_key", nullable = false, length = 128)
    private String groupKey;

    @Column(nullable = false, length = 16)
    private String status;

    @Column(name = "occurrence_count", nullable = false)
    private long occurrenceCount;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "alert_window", joinColumns = @JoinColumn(name = "alert_id"))
    @Column(name = "window_key", length = 256)
    private List<String> windowKeys = new ArrayList<>();

    @Column(name = "first_event_time", nullable = false)
    private Instant firstEventTime;

    @Column(name = "last_event_time", nullable = false)
    Instant lastEventTime;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @Column(name = "resolved_by", length = 128)
    private String resolvedBy;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public long getRuleId() { return ruleId; }
    public void setRuleId(long ruleId) { this.ruleId = ruleId; }
    public int getRuleVersion() { return ruleVersion; }
    public void setRuleVersion(int ruleVersion) { this.ruleVersion = ruleVersion; }
    public String getRuleCode() { return ruleCode; }
    public void setRuleCode(String ruleCode) { this.ruleCode = ruleCode; }
    public String getRuleSnapshotJson() { return ruleSnapshotJson; }
    public void setRuleSnapshotJson(String ruleSnapshotJson) { this.ruleSnapshotJson = ruleSnapshotJson; }
    public String getGroupKey() { return groupKey; }
    public void setGroupKey(String groupKey) { this.groupKey = groupKey; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public long getOccurrenceCount() { return occurrenceCount; }
    public void setOccurrenceCount(long occurrenceCount) { this.occurrenceCount = occurrenceCount; }
    public List<String> getWindowKeys() { return windowKeys; }
    public void setWindowKeys(List<String> windowKeys) { this.windowKeys = windowKeys; }
    public Instant getFirstEventTime() { return firstEventTime; }
    public void setFirstEventTime(Instant firstEventTime) { this.firstEventTime = firstEventTime; }
    public Instant getLastEventTime() { return lastEventTime; }
    public void setLastEventTime(Instant lastEventTime) { this.lastEventTime = lastEventTime; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant resolvedAt) { this.resolvedAt = resolvedAt; }
    public String getResolvedBy() { return resolvedBy; }
    public void setResolvedBy(String resolvedBy) { this.resolvedBy = resolvedBy; }
}
