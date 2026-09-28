package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.domain.EventView;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 规则匹配器：按<b>给定规则版本快照</b>判定事件是否匹配并计算分组键。
 *
 * <p>实时检测与离线对账/自愈共用同一套语义，保证“当时判定纳入了什么”可以用
 * 同样的规则版本复算：
 * <ul>
 *   <li>{@code matchConditions}：归一化字段或扩展属性的等值 AND；</li>
 *   <li>{@code groupBy}：分组字段；{@code __GLOBAL__} 或缺省表示全局分组；</li>
 *   <li>分组字段缺失的事件无法归组，按不匹配处理。</li>
 * </ul>
 */
@Component
public class RuleMatcher {

    private static final Logger log = LoggerFactory.getLogger(RuleMatcher.class);

    public static final String GLOBAL_GROUP = "__GLOBAL__";

    private final JsonService jsonService;

    public RuleMatcher(JsonService jsonService) {
        this.jsonService = jsonService;
    }

    /** 匹配返回分组键（全局分组为 {@link #GLOBAL_GROUP}）；不匹配或分组字段缺失返回 null。 */
    public String matchGroup(RuleEntity rule, EventView event) {
        Map<String, String> conditions = jsonService.readStringMap(rule.getMatchConditionsJson());
        for (Map.Entry<String, String> c : conditions.entrySet()) {
            String actual = extractField(event, c.getKey());
            if (actual == null || !actual.equals(c.getValue())) {
                return null;
            }
        }
        String groupBy = rule.getGroupBy();
        if (groupBy == null || groupBy.isBlank() || GLOBAL_GROUP.equals(groupBy)) {
            return GLOBAL_GROUP;
        }
        String groupKey = extractField(event, groupBy);
        if (groupKey == null) {
            // 分组字段缺失无法关联，按不匹配处理
            log.debug("事件 {} 缺少分组字段 {}，不归入规则 {}#v{}",
                    event.eventId(), groupBy, rule.getRuleCode(), rule.getVersion());
            return null;
        }
        return groupKey;
    }

    private String extractField(EventView event, String field) {
        return switch (field) {
            case "eventId" -> event.eventId();
            case "source" -> event.source();
            case "actor" -> event.actor();
            case "action" -> event.action();
            case "target" -> event.target();
            case "sourceIp" -> event.sourceIp();
            default -> event.attributes() == null ? null : event.attributes().get(field);
        };
    }
}
