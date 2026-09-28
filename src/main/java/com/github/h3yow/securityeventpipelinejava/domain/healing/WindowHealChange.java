package com.github.h3yow.securityeventpipelinejava.domain.healing;

import java.util.List;

/**
 * 单个窗口自愈事务的收敛结果（内部使用）。
 *
 * @param linkedBefore 收敛前 window_event 关联事件
 * @param expected     按规则版本复算应纳入的去重事件
 * @param added        本次补录进 window_event 的事件
 * @param removed      本次从 window_event 摘除的事件
 * @param alertId      收敛后 aggregate.matchedAlertId
 * @param alertAction  告警动作：CREATE / ATTACH_EXISTING / DETACH_RESOLVE / NONE
 * @param changed      该窗口是否发生任何实际变更
 */
public record WindowHealChange(
        String windowKey,
        List<String> linkedBefore,
        List<String> expected,
        List<String> added,
        List<String> removed,
        long beforeCount,
        long afterCount,
        boolean beforeFired,
        boolean afterFired,
        Long alertId,
        String alertAction,
        boolean changed
) {
}
