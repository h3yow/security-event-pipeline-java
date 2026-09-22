package com.github.h3yow.securityeventpipelinejava.web;

import java.util.Map;

/**
 * 原始日志接入请求。
 *
 * @param source  FIREWALL / AUTH
 * @param payload 原始字段（不同来源字段不同，归一化时校验）
 */
public record EventIngestRequest(String source, Map<String, Object> payload) {
}
