package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.domain.healing.HealOutcome;
import com.github.h3yow.securityeventpipelinejava.domain.healing.WindowHealChange;
import com.github.h3yow.securityeventpipelinejava.domain.healing.WindowHealResult;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.ReconciliationQuery;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowHealAuditEntity;
import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowHealAuditRepository;
import com.github.h3yow.securityeventpipelinejava.web.HealRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;

/**
 * 窗口自愈服务（运维入口）。
 *
 * <h3>语义</h3>
 * <ul>
 *   <li>扫描范围与对账查询一致（规则含版本/分组/窗口区间），对每个窗口用<b>当时规则版本</b>
 *       把 window_event / window_aggregate / 告警一并收敛到“按全部已受理去重事件”的正确状态；</li>
 *   <li><b>可重复触发、可并发触发</b>：按窗口键全局一致排序后逐窗口加 JVM 锁，每个窗口在
 *       独立短事务内修复，窗口间并行安全；收敛逻辑天然幂等，已正确窗口 changed=false 不动数据；</li>
 *   <li>与实时接入共用同一套 {@link WindowLockManager}：自愈与并发补录/重放互不覆盖；</li>
 *   <li>每次调用都追加一条 {@code window_heal_audit}：何时、谁、因何、扫描/修复了哪些窗口，
 *       审计只追加不修改，多次执行各留一条，结果一致。</li>
 * </ul>
 */
@Service
public class HealingService {

    private static final Logger log = LoggerFactory.getLogger(HealingService.class);

    private final WindowAggregateRepository aggregateRepository;
    private final RuleRepository ruleRepository;
    private final WindowHealAuditRepository auditRepository;
    private final WindowLockManager windowLockManager;
    private final WindowHealExecutor healExecutor;
    private final JsonService jsonService;

    public HealingService(WindowAggregateRepository aggregateRepository,
                          RuleRepository ruleRepository,
                          WindowHealAuditRepository auditRepository,
                          WindowLockManager windowLockManager,
                          WindowHealExecutor healExecutor,
                          JsonService jsonService) {
        this.aggregateRepository = aggregateRepository;
        this.ruleRepository = ruleRepository;
        this.auditRepository = auditRepository;
        this.windowLockManager = windowLockManager;
        this.healExecutor = healExecutor;
        this.jsonService = jsonService;
    }

    /**
     * 发起一次自愈。
     *
     * @param operator 操作者（X-Operator 头），仅用于审计
     * @param request  扫描范围与原因，可空
     */
    public HealOutcome heal(String operator, HealRequest request) {
        ReconciliationQuery q = request == null
                ? new ReconciliationQuery(null, null, null, null, null)
                : new ReconciliationQuery(request.ruleCode(), request.version(), request.groupKey(),
                        request.windowStartFrom(), request.windowStartTo());
        String reason = request == null || request.reason() == null || request.reason().isBlank()
                ? "MANUAL_RECONCILE" : request.reason();
        String triggeredBy = operator == null || operator.isBlank() ? "operator" : operator;

        List<WindowAggregateEntity> targets = new ArrayList<>(selectWindows(q));
        Map<Long, RuleEntity> ruleCache = new LinkedHashMap<>();

        // 按窗口键全局一致排序：自愈之间、自愈与实时接入均按同一顺序加锁，杜绝死锁
        targets.sort(Comparator.comparing(ReconciliationService::encodeWindowKey));
        List<WindowHealResult> results = new ArrayList<>(targets.size());

        for (WindowAggregateEntity aggregate : targets) {
            String windowKey = ReconciliationService.encodeWindowKey(aggregate);
            RuleEntity rule = ruleCache.computeIfAbsent(aggregate.getRuleId(),
                    id -> ruleRepository.findById(id).orElse(null));
            Lock lock = windowLockManager.lockFor(windowKey);
            lock.lock();
            try {
                // 锁内重新读取聚合（可能已被并发补录/另一次自愈修复），基于最新状态修复
                WindowAggregateEntity fresh = aggregateRepository
                        .findByRuleIdAndVersionAndGroupKeyAndWindowStart(
                                aggregate.getRuleId(), aggregate.getVersion(),
                                aggregate.getGroupKey(), aggregate.getWindowStart())
                        .orElse(aggregate);
                WindowHealChange change = healExecutor.healWindow(fresh, rule);
                results.add(new WindowHealResult(
                        change.windowKey(), change.changed(),
                        change.added(), change.removed(),
                        change.beforeCount(), change.afterCount(),
                        change.beforeFired(), change.afterFired(),
                        change.alertId(), change.alertAction()));
            } finally {
                lock.unlock();
            }
        }

        int healed = (int) results.stream().filter(WindowHealResult::changed).count();
        return recordAudit(triggeredBy, reason, targets.size(), healed, results);
    }

    private List<WindowAggregateEntity> selectWindows(ReconciliationQuery q) {
        return aggregateRepository.findAllByOrderByIdDesc().stream()
                .filter(a -> q.ruleCode() == null
                        || ruleRepository.findById(a.getRuleId())
                                .map(RuleEntity::getRuleCode).orElse("__UNKNOWN__").equals(q.ruleCode()))
                .filter(a -> q.version() == null || a.getVersion() == q.version())
                .filter(a -> q.groupKey() == null || q.groupKey().equals(a.getGroupKey()))
                .filter(a -> q.windowStartFrom() == null || a.getWindowStart() >= q.windowStartFrom())
                .filter(a -> q.windowStartTo() == null || a.getWindowStart() <= q.windowStartTo())
                .toList();
    }

    @Transactional
    public HealOutcome recordAudit(String triggeredBy, String reason, int scanned, int healed,
                                   List<WindowHealResult> results) {
        WindowHealAuditEntity audit = new WindowHealAuditEntity();
        Instant now = Instant.now();
        audit.setTriggeredAt(now);
        audit.setTriggeredBy(triggeredBy);
        audit.setReason(reason);
        audit.setScannedWindows(scanned);
        audit.setHealedWindows(healed);
        audit.setDetailsJson(jsonService.write(Map.of(
                "scanned", scanned,
                "healed", healed,
                "windows", results)));
        WindowHealAuditEntity saved = auditRepository.save(audit);
        log.info("窗口自愈完成: auditId={}, operator={}, reason={}, scanned={}, healed={}, results={}",
                saved.getId(), triggeredBy, reason, scanned, healed, results);
        return new HealOutcome(saved.getId(), now, triggeredBy, reason, scanned, healed,
                List.copyOf(results));
    }

    public List<WindowHealAuditEntity> auditTrail() {
        return auditRepository.findAllByOrderByIdDesc();
    }
}
