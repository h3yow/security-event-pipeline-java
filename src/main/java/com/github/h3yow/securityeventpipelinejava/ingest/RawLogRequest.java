package com.github.h3yow.securityeventpipelinejava.ingest;

import com.github.h3yow.securityeventpipelinejava.model.EventSource;

/**
 * 接入请求：source 指定解析器，eventId 为幂等键，payload 为原始报文。
 *
 * @param source   日志来源
 * @param eventId  来源系统的事件唯一标识
 * @param payload  原始报文（JSON 或 key=value 文本）
 */
public record RawLogRequest(EventSource source, String eventId, String payload) {
}
