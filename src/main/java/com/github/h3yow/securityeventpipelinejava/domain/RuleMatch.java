package com.github.h3yow.securityeventpipelinejava.domain;

/**
 * 事件与某条规则的匹配结果。
 *
 * @param ruleId   命中的规则ID
 * @param version  命中时规则的版本（保证规则变更后历史判定依据可追溯）
 * @param groupKey 分组键，例如 host-01
 */
public record RuleMatch(long ruleId, int version, String groupKey) {
}
