package com.github.h3yow.securityeventpipelinejava.domain;

import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;

/**
 * 事件对某条规则的判定目标：命中的规则版本 + 窗口键 + 窗口结束时间(epoch 秒)。
 */
public record WindowTarget(RuleEntity rule, WindowKey key, long windowEnd) {
}
