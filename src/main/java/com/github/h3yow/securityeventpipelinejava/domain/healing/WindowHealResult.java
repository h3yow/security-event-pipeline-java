package com.github.h3yow.securityeventpipelinejava.domain.healing;

import java.util.List;

/**
 * 单个窗口的自愈结果（对外）。
 */
public record WindowHealResult(
        String windowKey,
        boolean changed,
        List<String> addedEventIds,
        List<String> removedEventIds,
        long beforeCount,
        long afterCount,
        boolean beforeFired,
        boolean afterFired,
        Long alertId,
        String alertAction
) {
}
