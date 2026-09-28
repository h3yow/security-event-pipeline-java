package com.github.h3yow.securityeventpipelinejava.domain.reconciliation;

import java.time.Instant;
import java.util.List;

/**
 * 单个窗口的对账结果（骨架）。
 */
public record WindowReconciliationResult(
        String windowKey,
        long ruleId,
        String ruleCode,
        int version,
        String groupKey,
        Instant windowStart,
        Instant windowEnd,
        int threshold,
        long storedCount,
        long uniqueEventCount,
        long countDiff,
        boolean fired,
        boolean shouldFire,
        boolean countConsistent,
        boolean firingConsistent,
        boolean consistent,
        Long matchedAlertId,
        AlertBrief alert,
        List<String> missingEventIds,
        List<String> unexpectedEventIds,
        List<WindowContribution> contributions
) {
}
