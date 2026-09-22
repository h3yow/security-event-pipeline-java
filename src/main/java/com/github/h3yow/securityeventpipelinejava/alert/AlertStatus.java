package com.github.h3yow.securityeventpipelinejava.alert;

/** 告警生命周期状态机。 */
public enum AlertStatus {
    /** 新建 */
    OPEN,
    /** 已确认（分析师认领） */
    ACKNOWLEDGED,
    /** 调查中 */
    INVESTIGATING,
    /** 已解决（终态） */
    RESOLVED,
    /** 已抑制（终态，如同类告警风暴） */
    SUPPRESSED,
    /** 误报（终态） */
    FALSE_POSITIVE
}
