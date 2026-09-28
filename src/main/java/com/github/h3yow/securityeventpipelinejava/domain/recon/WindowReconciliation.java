package com.github.h3yow.securityeventpipelinejava.domain.recon;

import java.util.List;

/**
 * 单个窗口的对账结果（稳定、可解释）。
 *
 * <p>三方对账：①窗口当前统计值 storedCount；②window_event 去重关联行数 actualUniqueCount；
 * ③按"当时规则版本 + 已受理事件"重算的预期去重事件数 expectedCount。
 * 任一不一致都会在 boolean 差异标记与 missingEventIds / orphanEventIds 中直接体现，
 * 而不是只给一个总数。
 */
public record WindowReconciliation(
        long ruleId,
        String ruleCode,
        int ruleVersion,
        String groupKey,
        long windowStartEpoch,
        String windowStart,
        long windowEndEpoch,
        String windowEnd,
        int threshold,
        long storedCount,
        long actualUniqueCount,
        long expectedCount,
        boolean fired,
        boolean shouldFire,
        Long matchedAlertId,
        boolean consistent,
        boolean countMismatch,
        boolean firingMismatch,
        boolean alertMissing,
        boolean alertNotApplicable,
        List<String> missingEventIds,
        List<String> orphanEventIds,
        List<EventContribution> contributions
) {
}
