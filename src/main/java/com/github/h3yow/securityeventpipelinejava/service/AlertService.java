package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.common.AlertStatus;
import com.github.h3yow.securityeventpipelinejava.common.OperatorRole;
import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.common.RuleAction;
import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.domain.WindowKey;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.entity.AlertTransitionEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.domain.healing.AlertReconcileResult;
import com.github.h3yow.securityeventpipelinejava.exception.AccessDeniedException;
import com.github.h3yow.securityeventpipelinejava.exception.AlertStateException;
import com.github.h3yow.securityeventpipelinejava.exception.ResourceNotFoundException;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.AlertTransitionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 告警生命周期管理：去重合并、抑制、状态机流转与审计。
 *
 * <ul>
 *   <li>去重/合并：同规则同分组、距上次命中事件时间不超过 dedupSeconds 的活跃告警合并；</li>
 *   <li>抑制：规则 action=SUPPRESS 时新告警初始状态为 SUPPRESSED；</li>
 *   <li>状态机：合法转换见 {@link #canTransition}，RESOLVED 为终态，非法/越权转换被拒绝；</li>
 *   <li>每次流转写 alert_transition 审计表。</li>
 * </ul>
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);
    private static final List<String> ACTIVE = List.of(
            AlertStatus.OPEN.name(), AlertStatus.SUPPRESSED.name(), AlertStatus.ACKNOWLEDGED.name());

    private final AlertRepository alertRepository;
    private final AlertTransitionRepository transitionRepository;
    private final JsonService jsonService;

    /** 分组级合并锁，避免并发窗口命中重复建警。 */
    private final Map<String, Lock> groupLocks = new ConcurrentHashMap<>();
    /** 告警级状态锁，串行化同一告警的并发流转。 */
    private final Map<Long, Lock> alertLocks = new ConcurrentHashMap<>();

    public AlertService(AlertRepository alertRepository,
                        AlertTransitionRepository transitionRepository,
                        JsonService jsonService) {
        this.alertRepository = alertRepository;
        this.transitionRepository = transitionRepository;
        this.jsonService = jsonService;
    }

    public List<AlertEntity> listAlerts() {
        return alertRepository.findAllByOrderByIdDesc();
    }

    public AlertEntity get(long id) {
        return alertRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException(
                RejectReason.ALERT_NOT_FOUND, "告警不存在: " + id));
    }

    public List<AlertTransitionEntity> transitions(long alertId) {
        get(alertId);
        return transitionRepository.findByAlertIdOrderByIdAsc(alertId);
    }

    /**
     * 窗口达到阈值时调用：在 dedupSeconds 间隔内合并到活跃告警，否则新建告警。
     *
     * @return 命中的告警ID
     */
    @Transactional
    public long fireOrMerge(RuleEntity rule, WindowKey windowKey,
                            NormalizedEvent event, WindowAggregateEntity aggregate) {
        String groupLockKey = rule.getId() + ":" + windowKey.groupKey();
        Lock lock = groupLocks.computeIfAbsent(groupLockKey, k -> new ReentrantLock());
        lock.lock();
        try {
            AlertEntity existing = alertRepository
                    .findByRuleIdAndGroupKeyAndStatusInOrderByLastEventTimeDesc(
                            rule.getId(), windowKey.groupKey(), ACTIVE).stream()
                    .filter(a -> !a.getId().equals(aggregate.getMatchedAlertId()))
                    .filter(a -> Math.abs(Duration.between(
                            a.getLastEventTime(), event.eventTime()).toSeconds()) <= rule.getDedupSeconds())
                    .findFirst()
                    .orElse(null);

            if (existing != null) {
                existing.setOccurrenceCount(existing.getOccurrenceCount() + 1);
                if (!existing.getWindowKeys().contains(windowKey.encode())) {
                    existing.getWindowKeys().add(windowKey.encode());
                }
                if (event.eventTime().isAfter(existing.getLastEventTime())) {
                    existing.setLastEventTime(event.eventTime());
                }
                existing.setUpdatedAt(Instant.now());
                alertRepository.save(existing);
                aggregate.setMatchedAlertId(existing.getId());
                log.info("告警合并: alertId={}, rule={}#v{}, group={}, window={}, count={}, status={}",
                        existing.getId(), rule.getRuleCode(), rule.getVersion(), windowKey.groupKey(),
                        windowKey.encode(), aggregate.getCount(), existing.getStatus());
                return existing.getId();
            }

            AlertEntity alert = new AlertEntity();
            alert.setRuleId(rule.getId());
            alert.setRuleVersion(rule.getVersion());
            alert.setRuleCode(rule.getRuleCode());
            alert.setRuleSnapshotJson(jsonService.write(ruleSnapshot(rule)));
            alert.setGroupKey(windowKey.groupKey());
            AlertStatus initial = rule.getAction().equals(RuleAction.SUPPRESS.name())
                    ? AlertStatus.SUPPRESSED : AlertStatus.OPEN;
            alert.setStatus(initial.name());
            alert.setOccurrenceCount(1);
            alert.getWindowKeys().add(windowKey.encode());
            alert.setFirstEventTime(event.eventTime());
            alert.setLastEventTime(event.eventTime());
            Instant now = Instant.now();
            alert.setCreatedAt(now);
            alert.setUpdatedAt(now);
            AlertEntity saved = alertRepository.save(alert);
            aggregate.setMatchedAlertId(saved.getId());
            recordTransition(saved.getId(), null, initial, "system", "SYSTEM",
                    "窗口计数 " + aggregate.getCount() + " 达到阈值 " + rule.getThreshold() + " 自动建警");
            log.info("新建告警: alertId={}, rule={}#v{}, group={}, window={}, initialStatus={}",
                    saved.getId(), rule.getRuleCode(), rule.getVersion(), windowKey.groupKey(),
                    windowKey.encode(), initial);
            return saved.getId();
        } finally {
            lock.unlock();
        }
    }

    private Map<String, Object> ruleSnapshot(RuleEntity rule) {
        Map<String, Object> snapshot = new java.util.LinkedHashMap<>();
        snapshot.put("ruleId", rule.getId());
        snapshot.put("ruleCode", rule.getRuleCode());
        snapshot.put("version", rule.getVersion());
        snapshot.put("name", rule.getName());
        snapshot.put("matchConditions", jsonService.readStringMap(rule.getMatchConditionsJson()));
        snapshot.put("groupBy", rule.getGroupBy());
        snapshot.put("windowSeconds", rule.getWindowSeconds());
        snapshot.put("allowedLatenessSeconds", rule.getAllowedLatenessSeconds());
        snapshot.put("threshold", rule.getThreshold());
        snapshot.put("action", rule.getAction());
        snapshot.put("dedupSeconds", rule.getDedupSeconds());
        return snapshot;
    }

    /**
     * 告警状态流转。
     *
     * <pre>
     * OPEN          -> SUPPRESSED(ADMIN) / ACKNOWLEDGED(ADMIN,ANALYST) / RESOLVED(ADMIN,ANALYST)
     * SUPPRESSED    -> ACKNOWLEDGED(ADMIN,ANALYST) / RESOLVED(ADMIN)
     * ACKNOWLEDGED  -> OPEN(ADMIN) / RESOLVED(ADMIN,ANALYST)
     * RESOLVED      -> (终态，不允许任何转换)
     * </pre>
     */
    @Transactional
    public AlertEntity transition(long alertId, String targetStatusRaw, String operator,
                                  OperatorRole role, String note) {
        if (targetStatusRaw == null || targetStatusRaw.isBlank()) {
            throw new AlertStateException("缺少目标状态 targetStatus");
        }
        AlertStatus target;
        try {
            target = AlertStatus.valueOf(targetStatusRaw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new AlertStateException("未知的目标状态: " + targetStatusRaw);
        }
        if (role == null) {
            throw new AccessDeniedException("缺少 X-Operator-Role 请求头，无法鉴权");
        }
        AlertEntity alert = get(alertId);
        Lock lock = alertLocks.computeIfAbsent(alertId, k -> new ReentrantLock());
        lock.lock();
        try {
            alertRepository.flush();
            AlertStatus from = AlertStatus.valueOf(alert.getStatus());
            if (!canTransition(from, target)) {
                String msg = String.format(
                        "非法状态流转: 告警 %d 当前状态 %s 不允许转换到 %s（RESOLVED 为终态，允许的转换见状态机定义）",
                        alertId, from, target);
                log.warn(msg);
                throw new AlertStateException(msg);
            }
            if (!isAllowed(role, from, target)) {
                String msg = String.format(
                        "越权操作被拒绝: 角色 %s 不允许将告警 %d 从 %s 转换到 %s",
                        role, alertId, from, target);
                log.warn(msg);
                throw new AccessDeniedException(msg);
            }
            alert.setStatus(target.name());
            alert.setUpdatedAt(Instant.now());
            if (target == AlertStatus.RESOLVED) {
                alert.setResolvedAt(Instant.now());
                alert.setResolvedBy(operator);
            }
            alertRepository.save(alert);
            recordTransition(alertId, from, target, operator, role.name(), note);
            log.info("告警状态流转: alertId={}, {} -> {}, operator={}({}), note={}",
                    alertId, from, target, operator, role, note);
            return alert;
        } finally {
            lock.unlock();
        }
    }

    private boolean canTransition(AlertStatus from, AlertStatus to) {
        return switch (from) {
            case OPEN -> to == AlertStatus.SUPPRESSED || to == AlertStatus.ACKNOWLEDGED
                    || to == AlertStatus.RESOLVED;
            case SUPPRESSED -> to == AlertStatus.ACKNOWLEDGED || to == AlertStatus.RESOLVED;
            case ACKNOWLEDGED -> to == AlertStatus.OPEN || to == AlertStatus.RESOLVED;
            case RESOLVED -> false;
        };
    }

    private boolean isAllowed(OperatorRole role, AlertStatus from, AlertStatus to) {
        if (role == OperatorRole.ADMIN) {
            return true;
        }
        if (role == OperatorRole.VIEWER) {
            return false;
        }
        // ANALYST
        if (to == AlertStatus.RESOLVED) {
            return from == AlertStatus.OPEN || from == AlertStatus.ACKNOWLEDGED;
        }
        return to == AlertStatus.ACKNOWLEDGED;
    }

    private void recordTransition(long alertId, AlertStatus from, AlertStatus to,
                                  String operator, String role, String note) {
        AlertTransitionEntity t = new AlertTransitionEntity();
        t.setAlertId(alertId);
        t.setFromStatus(from == null ? null : from.name());
        t.setToStatus(to.name());
        t.setOperator(operator);
        t.setOperatorRole(role);
        t.setNote(note);
        t.setCreatedAt(Instant.now());
        transitionRepository.save(t);
    }

    /**
     * 窗口自愈时收敛告警关联，调用方须已持有该窗口锁（本方法不再加窗口锁）。
     *
     * <p>三种动作，幂等：
     * <ul>
     *   <li>{@code ATTACH_EXISTING}：窗口应触发且已有<b>活跃</b>告警携带该窗口键，
     *       不重复创建、不重复累计 occurrenceCount（RESOLVED 为终态，不算“仍适用”）；</li>
     *   <li>{@code CREATE}：窗口应触发但没有任何活跃告警支撑，按规则动作新建初始告警；</li>
     *   <li>{@code DETACH_RESOLVE}：窗口未达阈值却挂在告警上（误报）：从告警窗口列表移除；
     *       该告警再无其他窗口支撑时自动 RESOLVED 并写状态流转审计，仍支撑其他窗口则仅摘除、保留。</li>
     * </ul>
     * 仅在告警状态真正变化时写 alert_transition；窗口关联的增删统一记入自愈审计表。
     *
     * @return 收敛结果（告警ID + CREATE/ATTACH_EXISTING/DETACH_RESOLVE/NONE）
     */
    @Transactional
    public AlertReconcileResult reconcileForHealing(RuleEntity rule, WindowKey windowKey, long correctCount) {
        String encoded = windowKey.encode();
        List<AlertEntity> carrying = alertRepository.findByWindowKey(encoded);

        boolean shouldFire = correctCount >= rule.getThreshold();
        if (shouldFire) {
            // 仅活跃告警算“仍适用”；RESOLVED 是终态，应仿照实时语义另建新警
            AlertEntity active = carrying.stream()
                    .filter(a -> ACTIVE.contains(a.getStatus()))
                    .findFirst().orElse(null);
            if (active != null) {
                log.info("自愈: 窗口 {} 活跃告警已存在且仍适用，不重复创建/累计, alertId={}, status={}",
                        encoded, active.getId(), active.getStatus());
                return new AlertReconcileResult(active.getId(), "ATTACH_EXISTING");
            }
            // 应触发但无活跃告警：按规则动作新建（不改变任何既有告警的 occurrenceCount）
            AlertEntity alert = new AlertEntity();
            alert.setRuleId(rule.getId());
            alert.setRuleVersion(rule.getVersion());
            alert.setRuleCode(rule.getRuleCode());
            alert.setRuleSnapshotJson(jsonService.write(ruleSnapshot(rule)));
            alert.setGroupKey(windowKey.groupKey());
            AlertStatus initial = rule.getAction().equals(RuleAction.SUPPRESS.name())
                    ? AlertStatus.SUPPRESSED : AlertStatus.OPEN;
            alert.setStatus(initial.name());
            alert.setOccurrenceCount(1);
            alert.getWindowKeys().add(encoded);
            // 自愈场景没有单一触发事件：以窗口起点为事件时间
            Instant windowTime = Instant.ofEpochSecond(windowKey.windowStart());
            alert.setFirstEventTime(windowTime);
            alert.setLastEventTime(windowTime);
            Instant now = Instant.now();
            alert.setCreatedAt(now);
            alert.setUpdatedAt(now);
            AlertEntity saved = alertRepository.save(alert);
            recordTransition(saved.getId(), null, initial, "system", "HEALING",
                    "窗口自愈：按已受理去重事件复算 count=" + correctCount
                            + " 达阈值 " + rule.getThreshold() + "，补建告警");
            log.info("自愈: 窗口 {} 应触发但缺活跃告警，补建 alertId={}, initialStatus={}",
                    encoded, saved.getId(), initial);
            return new AlertReconcileResult(saved.getId(), "CREATE");
        }

        // 未达阈值：从携带该窗口键的告警上摘除；失去全部支撑窗口的活跃告警自动 RESOLVED（不误报）
        if (carrying.isEmpty()) {
            return new AlertReconcileResult(-1L, "NONE");
        }
        for (AlertEntity a : carrying) {
            if (!a.getWindowKeys().remove(encoded)) {
                continue;
            }
            a.setUpdatedAt(Instant.now());
            if (!a.getWindowKeys().isEmpty() || !ACTIVE.contains(a.getStatus())) {
                // 仍有其他窗口支撑，或本就是终态：仅摘除关联，状态不变（不写状态流转）
                alertRepository.save(a);
                log.info("自愈: 窗口 {} 未达阈值，从告警 {} 摘除关联（状态保持 {}，剩余支撑窗口 {} 个）",
                        encoded, a.getId(), a.getStatus(), a.getWindowKeys().size());
            } else {
                AlertStatus from = AlertStatus.valueOf(a.getStatus());
                a.setStatus(AlertStatus.RESOLVED.name());
                a.setResolvedAt(Instant.now());
                a.setResolvedBy("system(HEALING)");
                alertRepository.save(a);
                recordTransition(a.getId(), from, AlertStatus.RESOLVED, "system", "HEALING",
                        "窗口自愈：窗口 " + encoded + " 复算 count=" + correctCount
                                + " 未达阈值 " + rule.getThreshold() + "，且无其他支撑窗口，自动解除告警");
                log.info("自愈: 误报告警 {} 失去全部支撑窗口，{} -> RESOLVED", a.getId(), from);
            }
        }
        return new AlertReconcileResult(-1L, "DETACH_RESOLVE");
    }
}
