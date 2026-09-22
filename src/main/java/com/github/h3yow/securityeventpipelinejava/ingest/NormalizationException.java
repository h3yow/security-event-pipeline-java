package com.github.h3yow.securityeventpipelinejava.ingest;

import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;

/** 归一化失败异常，携带可区分的失败原因。 */
public class NormalizationException extends Exception {
    private final RejectionReason reason;

    public NormalizationException(RejectionReason reason, String detail) {
        super(detail);
        this.reason = reason;
    }

    public RejectionReason getReason() {
        return reason;
    }
}
