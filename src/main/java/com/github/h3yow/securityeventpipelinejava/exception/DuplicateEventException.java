package com.github.h3yow.securityeventpipelinejava.exception;

import static com.github.h3yow.securityeventpipelinejava.common.RejectReason.DUPLICATE_EVENT;

/** 同一 eventId 被重复提交。 */
public class DuplicateEventException extends PipelineException {
    public DuplicateEventException(String eventId) {
        super(DUPLICATE_EVENT, "事件已处理过，请勿重复提交: " + eventId);
    }
}
