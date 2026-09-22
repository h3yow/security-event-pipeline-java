package com.github.h3yow.securityeventpipelinejava.exception;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;

/** 原始日志校验/归一化失败。 */
public class ValidationException extends PipelineException {
    public ValidationException(RejectReason reason, String message) {
        super(reason, message);
    }
}
