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

/**
 * 检测规则（版本化）。更新规则时插入新版本行，旧版本保留，
 * 历史窗口与告警引用当时的 version，判定依据可追溯。
 */
@Entity
@Table(name = "detection_rule",
        uniqueConstraints = @UniqueConstraint(name = "uk_rule_code_version", columnNames = {"rule_code", "version"}))
public class RuleEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_code", nullable = false, length = 64)
    private String ruleCode;

    @Column(nullable = false)
    private int version;

    @Column(nullable = false, length = 128)
    private String name;

    /** 归一化事件字段的匹配条件，JSON：{"action":"LOGIN_FAIL","target":"/api/login"}，AND 语义。 */
    @Lob
    @Column(name = "match_conditions_json", nullable = false)
    private String matchConditionsJson;

    /** 分组字段名，例如 sourceIp / actor；可为空表示全局计数。 */
    @Column(name = "group_by", length = 64)
    private String groupBy;

    /** 窗口大小（秒）。 */
    @Column(name = "window_seconds", nullable = false)
    private long windowSeconds;

    /** 允许迟到时间（秒），基于接入时刻墙上时钟判定。 */
    @Column(name = "allowed_lateness_seconds", nullable = false)
    private long allowedLatenessSeconds;

    /** 窗口内计数达到该阈值即命中。 */
    @Column(nullable = false)
    private int threshold;

    /** 命中动作：ALERT / SUPPRESS。 */
    @Column(nullable = false, length = 16)
    private String action;

    /** 同规则活跃告警的合并间隔（秒）：窗口间连续命中合并为一条告警。 */
    @Column(name = "dedup_seconds", nullable = false)
    private long dedupSeconds;

    @Column(nullable = false)
    private boolean enabled = true;

    /**
     * 该版本停止生效的时刻：被下一版本取代时写入下一版本的 createdAt；
     * 当前生效版本为 null。对账/自愈据此界定“事件受理时命中的是不是这个版本”，
     * 避免升级后受理的事件被错误地复算进旧版本窗口。
     */
    @Column(name = "superseded_at")
    private Instant supersededAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getRuleCode() { return ruleCode; }
    public void setRuleCode(String ruleCode) { this.ruleCode = ruleCode; }
    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getMatchConditionsJson() { return matchConditionsJson; }
    public void setMatchConditionsJson(String matchConditionsJson) { this.matchConditionsJson = matchConditionsJson; }
    public String getGroupBy() { return groupBy; }
    public void setGroupBy(String groupBy) { this.groupBy = groupBy; }
    public long getWindowSeconds() { return windowSeconds; }
    public void setWindowSeconds(long windowSeconds) { this.windowSeconds = windowSeconds; }
    public long getAllowedLatenessSeconds() { return allowedLatenessSeconds; }
    public void setAllowedLatenessSeconds(long allowedLatenessSeconds) { this.allowedLatenessSeconds = allowedLatenessSeconds; }
    public int getThreshold() { return threshold; }
    public void setThreshold(int threshold) { this.threshold = threshold; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public long getDedupSeconds() { return dedupSeconds; }
    public void setDedupSeconds(long dedupSeconds) { this.dedupSeconds = dedupSeconds; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getSupersededAt() { return supersededAt; }
    public void setSupersededAt(Instant supersededAt) { this.supersededAt = supersededAt; }
}
