package com.github.h3yow.securityeventpipelinejava.domain;

import java.util.List;

/**
 * 事件接入结果。accepted=false 时 reason 给出可区分的拒绝原因。
 */
public record IngestResult(
        boolean accepted,
        String eventId,
        RejectInfo rejection,
        List<Long> alertIds
) {
    public record RejectInfo(String reason, String message) {
    }

    public static IngestResult ok(String eventId, List<Long> alertIds) {
        return new IngestResult(true, eventId, null, alertIds);
    }

    public static IngestResult rejected(String eventId, String reason, String message) {
        return new IngestResult(false, eventId, new RejectInfo(reason, message), List.of());
    }
}
