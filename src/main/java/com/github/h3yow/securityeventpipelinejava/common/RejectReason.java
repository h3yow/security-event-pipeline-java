package com.github.h3yow.securityeventpipelinejava.common;

/**
 * 记录被拒绝 / 处理失败的可区分原因。
 */
public enum RejectReason {
    MISSING_FIELD,
    ILLEGAL_FORMAT,
    INVALID_TIMESTAMP,
    TIMESTAMP_OUT_OF_RANGE,
    DUPLICATE_EVENT,
    WINDOW_EXPIRED,
    UNKNOWN_SOURCE,
    RULE_NOT_FOUND,
    ILLEGAL_STATE_TRANSITION,
    ACCESS_DENIED,
    ALERT_NOT_FOUND,
    INTERNAL_ERROR
}
