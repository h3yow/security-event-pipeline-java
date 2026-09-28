package com.github.h3yow.securityeventpipelinejava.domain.healing;

/**
 * 自愈时单个窗口的告警收敛结果。
 *
 * @param alertId 收敛后承载该窗口的活跃告警ID；未达阈值无告警时为 -1
 * @param action  CREATE（补建）/ ATTACH_EXISTING（复用已有活跃告警，不重复累计）
 *                / DETACH_RESOLVE（摘除关联，可能伴随自动 RESOLVED）/ NONE（无需动作）
 */
public record AlertReconcileResult(long alertId, String action) {
}
