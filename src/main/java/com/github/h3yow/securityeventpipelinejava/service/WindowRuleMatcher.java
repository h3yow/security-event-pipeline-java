
package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.domain.RuleMatch;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;

import java.util.Map;

/**
 * 规则匹配口径（归一化事件字段等值 AND 匹配 + 分组取值）。
 *
 * <p>检测接入与窗口对账/自愈<b>共用同一套口径</b>，保证"当时实际判定应纳入哪些事件"
 * 与实时检测完全一致：对账重算预期事件集时不会因为口径漂移而误报差异。
 */
public final class WindowRuleMatcher {

    private WindowRuleMatcher() {
    }

    /** 匹配返回 RuleMatch(含分组值)；不匹配或分组字段缺失返回 null。 */
    public static RuleMatch match(RuleEntity rule, NormalizedEvent event, JsonService jsonService) {
        Map<String, String> conditions = jsonService.readStringMap(rule.getMatchConditionsJson());
        for (Map.Entry<String, String> c : conditions.entrySet()) {
            String actual = DetectionService.extractField(event, c.getKey());
            if (actual == null || !actual.equals(c.getValue())) {
                return null;
            }
        }
        String groupKey = "__GLOBAL__".equals(rule.getGroupBy())
                ? "__GLOBAL__"
                : DetectionService.extractField(event, rule.getGroupBy());
        if (groupKey == null) {
            // 分组字段缺失无法关联，按不匹配处理（归一化阶段已保证必填字段存在）
            return null;
        }
        return new RuleMatch(rule.getId(), rule.getVersion(), groupKey);
    }
}
