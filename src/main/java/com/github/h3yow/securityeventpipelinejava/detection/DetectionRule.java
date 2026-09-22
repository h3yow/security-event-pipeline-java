package com.github.h3yow.securityeventpipelinejava.detection;

import jakarta.persistence.*;

/**
 * 检测规则（版本化）。规则变更产生新版本行，历史告警仍引用旧版本，
 * 保证判定依据可追溯。
 */
@Entity
@Table(name = "detection_rule",
        uniqueConstraints = @UniqueConstraint(columnNames = {"ruleId", "version"}))
public class DetectionRule {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 规则业务标识，如 BRUTE_FORCE_LOGIN */
    @Column(nullable = false, length = 64)
    private String ruleId;

    /** 规则版本，从 1 开始单调递增 */
    @Column(nullable = false)
    private int version;

    /** 匹配的事件动作，如 LOGIN_FAIL */
    @Column(nullable = false, length = 64)
    private String action;

    /** 滑动窗口长度（秒） */
    @Column(nullable = false)
    private long windowSeconds;

    /** 触发阈值：窗口内事件数 >= threshold 触发 */
    @Column(nullable = false)
    private int threshold;

    /** 允许的最大迟到时间（秒）：事件时间早于 水位线-maxLateness 的事件被拒绝 */
    @Column(nullable = false)
    private long maxLatenessSeconds;

    @Column(nullable = false)
    private boolean enabled;

    protected DetectionRule() {}

    public DetectionRule(String ruleId, int version, String action, long windowSeconds,
                         int threshold, long maxLatenessSeconds, boolean enabled) {
        this.ruleId = ruleId;
        this.version = version;
        this.action = action;
        this.windowSeconds = windowSeconds;
        this.threshold = threshold;
        this.maxLatenessSeconds = maxLatenessSeconds;
        this.enabled = enabled;
    }

    public Long getId() { return id; }
    public String getRuleId() { return ruleId; }
    public int getVersion() { return version; }
    public String getAction() { return action; }
    public long getWindowSeconds() { return windowSeconds; }
    public int getThreshold() { return threshold; }
    public long getMaxLatenessSeconds() { return maxLatenessSeconds; }
    public boolean isEnabled() { return enabled; }
}
