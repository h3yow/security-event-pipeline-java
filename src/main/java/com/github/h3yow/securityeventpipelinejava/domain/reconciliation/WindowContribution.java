package com.github.h3yow.securityeventpipelinejava.domain.reconciliation;

import java.time.Instant;

/**
 * 单个事件对窗口统计的贡献摘要（骨架）。
 */
public record WindowContribution(
        String eventId,
        Instant eventTime,
        Instant ingestTime,
        String actor,
        String action,
        String target,
        String sourceIp
) {
}
