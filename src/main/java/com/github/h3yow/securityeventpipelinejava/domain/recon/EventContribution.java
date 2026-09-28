package com.github.h3yow.securityeventpipelinejava.domain.recon;

/**
 * 单个事件对某个窗口统计的贡献摘要。
 *
 * @param eventId      事件ID
 * @param eventTime    事件时间（ISO-8601）
 * @param counted      是否计入该窗口统计
 * @param category     分类：COUNTED(正确计入) / MISSING(应计入但关联缺失) /
 *                     ORPHAN(有关联行但按当前口径不应计入)
 * @param detail       人类可读说明
 */
public record EventContribution(
        String eventId,
        String eventTime,
        boolean counted,
        String category,
        String detail
) {
}
