package com.github.h3yow.securityeventpipelinejava.domain.reconciliation;

/**
 * 对账查询条件（骨架）。全部可空；时间为窗口起点的 epoch 秒闭区间。
 */
public record ReconciliationQuery(
        String ruleCode,
        Integer version,
        String groupKey,
        Long windowStartFrom,
        Long windowStartTo
) {
}
