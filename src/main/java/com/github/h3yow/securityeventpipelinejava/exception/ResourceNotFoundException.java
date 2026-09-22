package com.github.h3yow.securityeventpipelinejava.exception;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;

/** 资源不存在。 */
public class ResourceNotFoundException extends PipelineException {
    public ResourceNotFoundException(RejectReason reason, String message) {
        super(reason, message);
    }
}
