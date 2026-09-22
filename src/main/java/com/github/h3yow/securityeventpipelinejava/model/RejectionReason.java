package com.github.h3yow.securityeventpipelinejava.model;

/** 记录被拒绝时的可区分原因。 */
public enum RejectionReason {
    /** 必填字段缺失 */
    MISSING_FIELD,
    /** 报文格式非法，无法解析 */
    INVALID_FORMAT,
    /** 时间戳缺失、非法或超出合理范围 */
    INVALID_TIMESTAMP,
    /** 事件时间早于允许的最大迟到窗口 */
    TOO_LATE,
    /** 同一 eventId 已被处理过（幂等去重） */
    DUPLICATE
}
