package com.github.h3yow.securityeventpipelinejava.domain.healing;

import java.time.Instant;
import java.util.List;

/**
 * 一次自愈调用的总体结果（对应一条 window_heal_audit 审计记录）。
 */
public record HealOutcome(
        long auditId,
        Instant triggeredAt,
        String triggeredBy,
        String reason,
        int scannedWindows,
        int healedWindows,
        List<WindowHealResult> windows
) {
}
