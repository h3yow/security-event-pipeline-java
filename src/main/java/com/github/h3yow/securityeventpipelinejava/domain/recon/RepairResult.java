package com.github.h3yow.securityeventpipelinejava.domain.recon;

import java.util.List;

/**
 * 一次窗口自愈的结果。重复/并发触发后对同一批窗口反复执行，本结果必须收敛一致。
 */
public record RepairResult(
        long auditId,
        String triggerReason,
        String operator,
        int scannedWindows,
        int changedWindows,
        List<WindowRepairAction> actions
) {
}
