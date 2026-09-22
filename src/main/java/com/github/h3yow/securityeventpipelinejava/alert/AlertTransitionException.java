package com.github.h3yow.securityeventpipelinejava.alert;

/** 非法或越权状态变更异常，message 说明具体原因。 */
public class AlertTransitionException extends RuntimeException {

    public enum Kind {
        /** 状态机不允许的流转 */
        ILLEGAL_TRANSITION,
        /** 角色无权执行该流转 */
        FORBIDDEN_ROLE,
        /** 告警不存在 */
        ALERT_NOT_FOUND
    }

    private final Kind kind;

    public AlertTransitionException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind getKind() {
        return kind;
    }
}
