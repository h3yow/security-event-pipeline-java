package com.github.h3yow.securityeventpipelinejava.model;

/** 支持的日志来源类型。 */
public enum EventSource {
    /** JSON 格式的防火墙日志 */
    FIREWALL,
    /** key=value 文本格式的认证日志 */
    AUTH,
    /** JSON 格式的 IDS 日志 */
    IDS
}
