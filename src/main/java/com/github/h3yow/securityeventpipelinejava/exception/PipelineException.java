package com.github.h3yow.securityeventpipelinejava.exception;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;

/**
 * 流水线业务异常基类：携带可区分的失败原因。
 */
public class PipelineException extends RuntimeException {
    private final RejectReason reason;

    public PipelineException(RejectReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectReason getReason() {
        return reason;
    }
}
