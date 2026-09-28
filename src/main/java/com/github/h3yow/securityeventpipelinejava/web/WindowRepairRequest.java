package com.github.h3yow.securityeventpipelinejava.web;

/**
 * 窗口自愈请求。scope 与对账查询一致；onlyInconsistent=true 时只处理对账不一致的窗口。
 */
public record WindowRepairRequest(
        String ruleCode,
        Integer ruleVersion,
        String groupKey,
        String from,
        String to,
        Boolean onlyInconsistent,
        String triggerReason
) {
}
