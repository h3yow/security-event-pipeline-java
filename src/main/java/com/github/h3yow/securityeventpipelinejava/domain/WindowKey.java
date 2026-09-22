package com.github.h3yow.securityeventpipelinejava.domain;

/**
 * 规则窗口的唯一标识：规则 + 版本 + 分组 + 窗口起点（事件时间对齐）。
 */
public record WindowKey(long ruleId, int version, String groupKey, long windowStart) {
    public String encode() {
        return ruleId + "#v" + version + "#" + groupKey + "#" + windowStart;
    }
}
