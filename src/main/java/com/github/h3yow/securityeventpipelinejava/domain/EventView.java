package com.github.h3yow.securityeventpipelinejava.domain;

import java.time.Instant;
import java.util.Map;

/**
 * 规则匹配所需的事件只读视图（实时归一化事件与历史事件实体共用）。
 */
public interface EventView {
    String eventId();
    String source();
    Instant eventTime();
    String actor();
    String action();
    String target();
    String sourceIp();
    Map<String, String> attributes();
}
