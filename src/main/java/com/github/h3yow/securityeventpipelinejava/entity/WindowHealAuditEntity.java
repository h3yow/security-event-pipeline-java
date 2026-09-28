package com.github.h3yow.securityeventpipelinejava.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * 窗口自愈审计记录（骨架）：何时、因何、处理了哪些窗口。
 */
@Entity
@Table(name = "window_heal_audit")
public class WindowHealAuditEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "triggered_at", nullable = false)
    private Instant triggeredAt;

    @Column(name = "triggered_by", length = 128)
    private String triggeredBy;

    @Column(length = 256)
    private String reason;

    @Column(name = "scanned_windows", nullable = false)
    private int scannedWindows;

    @Column(name = "healed_windows", nullable = false)
    private int healedWindows;

    @Lob
    @Column(name = "details_json", nullable = false)
    private String detailsJson;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Instant getTriggeredAt() { return triggeredAt; }
    public void setTriggeredAt(Instant triggeredAt) { this.triggeredAt = triggeredAt; }
    public String getTriggeredBy() { return triggeredBy; }
    public void setTriggeredBy(String triggeredBy) { this.triggeredBy = triggeredBy; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public int getScannedWindows() { return scannedWindows; }
    public void setScannedWindows(int scannedWindows) { this.scannedWindows = scannedWindows; }
    public int getHealedWindows() { return healedWindows; }
    public void setHealedWindows(int healedWindows) { this.healedWindows = healedWindows; }
    public String getDetailsJson() { return detailsJson; }
    public void setDetailsJson(String detailsJson) { this.detailsJson = detailsJson; }
}
