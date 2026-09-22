package com.github.h3yow.securityeventpipelinejava.ingest;

import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;

/**
 * 接入结果。
 *
 * @param accepted 是否被接受
 * @param eventId  事件标识
 * @param reason   拒绝原因（接受时为 null）
 * @param detail   人类可读的说明
 */
public record IngestResult(boolean accepted, String eventId, RejectionReason reason, String detail) {

    public static IngestResult accepted(String eventId) {
        return new IngestResult(true, eventId, null, "accepted");
    }

    public static IngestResult rejected(String eventId, RejectionReason reason, String detail) {
        return new IngestResult(false, eventId, reason, detail);
    }
}
