package com.github.h3yow.securityeventpipelinejava.common;

/** 操作员角色（通过 X-Operator-Role 请求头传入，仅用于本地演示）。 */
public enum OperatorRole {
    ADMIN,
    ANALYST,
    VIEWER
}
