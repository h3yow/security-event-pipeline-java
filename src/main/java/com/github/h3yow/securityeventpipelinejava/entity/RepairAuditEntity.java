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
 * 窗口自愈审计：每次发起修复（即使没有窗口发生变化）都留一条记录，
 * 说明何时、由谁、因何原因、对哪些窗口做了什么处理，以及每个窗口修复前后的状态。
 */
@Entity
@Table(name = "repair_audit")
public class RepairAuditEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 触发原因（调用方提供的说明），如"对账发现 count 与去重事件数不一致"。 */
    @Lob
    @Column(name = "trigger_reason", nullable = false)
    private String triggerReason;

    @Column(length = 128)
    private String operator;

    @Column(name = "operator_role", length = 32)
    private String operatorRole;

    /** 本次扫描的窗口范围（规则/分组/区间），JSON。 */
    @Lob
    @Column(name = "scope_json")
    private String scopeJson;

    /** 扫描到的窗口数。 */
    @Column(name = "scanned_windows", nullable = false)
    private int scannedWindows;

    /** 实际发生状态变化的窗口数（0 表示幂等空跑）。 */
    @Column(name = "changed_windows", nullable = false)
    private int changedWindows;

    /** 每个窗口的处理动作明细，JSON。 */
    @Lob
    @Column(name = "actions_json", nullable = false)
    private String actionsJson;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTriggerReason() { return triggerReason; }
    public void setTriggerReason(String triggerReason) { this.triggerReason = triggerReason; }
    public String getOperator() { return operator; }
    public void setOperator(String operator) { this.operator = operator; }
    public String getOperatorRole() { return operatorRole; }
    public void setOperatorRole(String operatorRole) { this.operatorRole = operatorRole; }
    public String getScopeJson() { return scopeJson; }
    public void setScopeJson(String scopeJson) { this.scopeJson = scopeJson; }
    public int getScannedWindows() { return scannedWindows; }
    public void setScannedWindows(int scannedWindows) { this.scannedWindows = scannedWindows; }
    public int getChangedWindows() { return changedWindows; }
    public void setChangedWindows(int changedWindows) { this.changedWindows = changedWindows; }
    public String getActionsJson() { return actionsJson; }
    public void setActionsJson(String actionsJson) { this.actionsJson = actionsJson; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
