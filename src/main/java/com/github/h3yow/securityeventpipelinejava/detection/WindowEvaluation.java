package com.github.h3yow.securityeventpipelinejava.detection;

import java.time.Instant;
import java.util.List;

/**
 * 一次窗口评估的判定依据（随告警持久化，保证可解释、可追溯）。
 *
 * @param ruleId        规则标识
 * @param ruleVersion   评估时使用的规则版本
 * @param groupKey      分组键
 * @param windowStart   窗口起点（含）
 * @param windowEnd     窗口终点（含）
 * @param count         窗口内匹配事件数
 * @param threshold     触发阈值
 * @param triggered     是否触发
 * @param eventIds      窗口内参与计数的事件 id 列表
 */
public record WindowEvaluation(String ruleId, int ruleVersion, String groupKey,
                               Instant windowStart, Instant windowEnd,
                               int count, int threshold, boolean triggered,
                               List<String> eventIds) {
}
