package com.github.h3yow.securityeventpipelinejava.domain.reconciliation;

/**
 * 窗口关联告警的简要信息（骨架）。
 */
public record AlertBrief(long id, String status, long occurrenceCount, int windowKeyCount) {
}
