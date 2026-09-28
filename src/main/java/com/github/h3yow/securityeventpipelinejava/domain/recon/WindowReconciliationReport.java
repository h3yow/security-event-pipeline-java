package com.github.h3yow.securityeventpipelinejava.domain.recon;

import java.util.List;

/**
 * 一次窗口对账查询的完整结果。
 *
 * @param ruleCode       查询规则编码
 * @param ruleVersion    指定的规则版本（null 表示该规则全部版本）
 * @param groupKey       指定分组（可空）
 * @param from           窗口起始下界（可空，ISO-8601）
 * @param to             窗口起始上界（可空，ISO-8601）
 * @param totalWindows   命中窗口数
 * @param inconsistentWindows 其中不一致的窗口数
 * @param windows        每个窗口的对账明细，按规则版本/分组/窗口起点稳定排序
 */
public record WindowReconciliationReport(
        String ruleCode,
        Integer ruleVersion,
        String groupKey,
        String from,
        String to,
        long totalWindows,
        long inconsistentWindows,
        List<WindowReconciliation> windows
) {
}
