package com.github.h3yow.securityeventpipelinejava.exception;

import static com.github.h3yow.securityeventpipelinejava.common.RejectReason.ILLEGAL_STATE_TRANSITION;

/** 非法的告警状态流转。 */
public class AlertStateException extends PipelineException {
    public AlertStateException(String message) {
        super(ILLEGAL_STATE_TRANSITION, message);
    }
}
