package com.github.h3yow.securityeventpipelinejava.exception;

import static com.github.h3yow.securityeventpipelinejava.common.RejectReason.ACCESS_DENIED;

/** 越权操作。 */
public class AccessDeniedException extends PipelineException {
    public AccessDeniedException(String message) {
        super(ACCESS_DENIED, message);
    }
}
