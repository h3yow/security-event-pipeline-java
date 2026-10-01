package com.github.h3yow.securityeventpipelinejava.domain.recon;

/**
 * 单个事件对某个窗口统计的贡献摘要。
 *
 * @param eventId      事件ID
 * @param eventTime    事件时间（ISO-8601）
 * @param counted      是否计入该窗口统计
 * @param category     分类：
 *                     <ul>
 *                       <li>COUNTED(正确计入)：受理于该版本生效期、符合口径且关联存在；</li>
 *                       <li>MISSING(应计入但关联缺失，少算)；</li>
 *                       <li>ORPHAN(有关联行但按该版本受理时口径不应纳入，多算)；</li>
 *                       <li>EXCLUDED_OTHER_VERSION(事件时间虽落入本窗口、也符合本版本匹配条件，
 *                           但受理时刻生效的是另一个规则版本，归属对应版本窗口，本版本既不算缺失也不算多算)。</li>
 *                     </ul>
 * @param detail       人类可读说明（含受理时刻与版本边界，升级边界可解释）
 */
public record EventContribution(
        String eventId,
        String eventTime,
        boolean counted,
        String category,
        String detail
) {
}
