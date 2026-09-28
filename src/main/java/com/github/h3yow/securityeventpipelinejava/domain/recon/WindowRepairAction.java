package com.github.h3yow.securityeventpipelinejava.domain.recon;

import java.util.List;

/**
 * 自愈对单个窗口执行的动作明细（写入审计，可直接解释"改了什么"）。
 */
public record WindowRepairAction(
        String windowKey,
        String ruleCode,
        int ruleVersion,
        String groupKey,
        long windowStartEpoch,
        boolean changed,
        long countBefore,
        long countAfter,
        boolean firedBefore,
        boolean firedAfter,
        Long alertIdBefore,
        Long alertIdAfter,
        /** ADDED_MEMBER / REMOVED_ORPHAN / COUNT_CORRECTED / FIRE_ALERT_CREATED /
         *  FALSE_ALERT_CLEARED / FALSE_ALERT_DELETED / NO_CHANGE / MANUAL_REVIEW_REQUIRED */
        List<String> actions,
        List<String> addedEventIds,
        List<String> removedEventIds,
        String note
) {
}
