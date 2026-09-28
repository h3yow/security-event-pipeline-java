package com.github.h3yow.securityeventpipelinejava.web;

/**
 * 窗口自愈请求体（骨架）。字段均可空：默认按与对账相同的条件扫描全部窗口。
 */
public record HealRequest(
        String ruleCode,
        Integer version,
        String groupKey,
        Long windowStartFrom,
        Long windowStartTo,
        String reason
) {
}
