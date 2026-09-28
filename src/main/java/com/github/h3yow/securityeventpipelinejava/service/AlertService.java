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
import java.util.Comparator;
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

    /**
     * 自愈专用：确保一个已达阈值的窗口存在且仅关联一条"仍适用"的告警。
     *
     * <p>查找顺序（幂等、不重复创建、不重复累计）：
     * <ol>
     *   <li>aggregate 当前关联的告警仍包含该窗口键 => 直接复用；</li>
     *   <li>其它仍包含该窗口键的告警（历史漂移导致关联错位）=> 改关联到它，不新建；</li>
     *   <li>否则按实时检测相同的合并口径：dedupSeconds 内的同规则同分组活跃告警合并
     *       （仅在该告警尚未包含此窗口时 +1 次，保证不重复累计）；</li>
     *   <li>都没有 => 新建一条告警并写自动建警流转。</li>
     * </ol>
     * 调用方必须已持有该窗口锁并处于事务中。
     *
     * @return 关联到的告警ID
     */
    @Transactional
    public long ensureAlertForWindow(RuleEntity rule, WindowKey windowKey,
                                     WindowAggregateEntity aggregate,
                                     Instant referenceEventTime) {
        String windowKeyEncoded = windowKey.encode();
        // 1) 已有关联且仍适用
        if (aggregate.getMatchedAlertId() != null) {
            AlertEntity linked = alertRepository.findById(aggregate.getMatchedAlertId()).orElse(null);
            if (linked != null && linked.getWindowKeys().contains(windowKeyEncoded)) {
                return linked.getId();
            }
        }
        // 2) 其它告警已包含该窗口（关联错位的修复：改挂回去，绝不新建；窗口键已含分组，不再限组）
        AlertEntity owner = alertRepository.findAll().stream()
                .filter(a -> a.getRuleId() == rule.getId())
                .filter(a -> a.getWindowKeys().contains(windowKeyEncoded))
                .min(Comparator.comparingLong(AlertEntity::getId))
                .orElse(null);
        if (owner != null) {
            aggregate.setMatchedAlertId(owner.getId());
            log.info("自愈: 窗口 {} 改关联到已包含该窗口的告警 {}", windowKeyEncoded, owner.getId());
            return owner.getId();
        }
        // 3) dedup 合并口径：与实时检测相同（基于窗口内最新事件时间）
        AlertEntity mergeTarget = alertRepository
                .findByRuleIdAndGroupKeyAndStatusInOrderByLastEventTimeDesc(
                        rule.getId(), windowKey.groupKey(), ACTIVE).stream()
                .filter(a -> Math.abs(Duration.between(
                        a.getLastEventTime(), referenceEventTime).toSeconds()) <= rule.getDedupSeconds())
                .findFirst().orElse(null);
        if (mergeTarget != null) {
            if (!mergeTarget.getWindowKeys().contains(windowKeyEncoded)) {
                mergeTarget.setOccurrenceCount(mergeTarget.getOccurrenceCount() + 1);
                mergeTarget.getWindowKeys().add(windowKeyEncoded);
            }
            if (referenceEventTime.isAfter(mergeTarget.getLastEventTime())) {
                mergeTarget.setLastEventTime(referenceEventTime);
            }
            mergeTarget.setUpdatedAt(Instant.now());
            alertRepository.save(mergeTarget);
            aggregate.setMatchedAlertId(mergeTarget.getId());
            log.info("自愈: 窗口 {} 合并进活跃告警 {}", windowKeyEncoded, mergeTarget.getId());
            return mergeTarget.getId();
        }
        // 4) 新建
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
        alert.getWindowKeys().add(windowKeyEncoded);
        alert.setFirstEventTime(referenceEventTime);
        alert.setLastEventTime(referenceEventTime);
        Instant now = Instant.now();
        alert.setCreatedAt(now);
        alert.setUpdatedAt(now);
        AlertEntity saved = alertRepository.save(alert);
        aggregate.setMatchedAlertId(saved.getId());
        recordTransition(saved.getId(), null, initial, "system-heal", "SYSTEM",
                "窗口自愈：去重事件数 " + aggregate.getCount() + " 达到阈值 " + rule.getThreshold()
                        + "，补建告警");
        log.info("自愈: 窗口 {} 补建告警 {}", windowKeyEncoded, saved.getId());
        return saved.getId();
    }

    /**
     * 自愈专用：解除一个未达阈值窗口的误报告警关联。
     *
     * <p>从告警的窗口列表移除该窗口并 occurrenceCount-1；若该告警因此不再关联任何窗口、
     * 处于 OPEN/SUPPRESSED（未被人工处置过）且只有建警流转，则删除告警及其流转
     * （它本就是误报，其自动建警记录随误报一起作废，修复审计另行留痕）。
     * 其余情况（ACK/RESOLVED、已有人工流转、occurrenceCount 归零但状态非初始）保留告警，
     * 返回 needsManualReview=true 交运维人工处理，绝不擅自删除已处置告警。
     *
     * @return 处理结果：alertId 为受影响告警（无则 null），deleted 表示是否已删除，
     *         needsManualReview 表示是否需要人工复核
     */
    @Transactional
    public AlertClearResult clearAlertForWindow(WindowKey windowKey, Long linkedAlertId) {
        String windowKeyEncoded = windowKey.encode();
        Long effectiveId = linkedAlertId;
        AlertEntity alert = effectiveId == null ? null
                : alertRepository.findById(effectiveId).orElse(null);
        if (alert == null) {
            // 关联指向的告警已不存在；再找有没有其它告警错误包含此窗口
            alert = alertRepository.findAll().stream()
                    .filter(a -> a.getWindowKeys().contains(windowKeyEncoded))
                    .min(Comparator.comparingLong(AlertEntity::getId)).orElse(null);
        }
        if (alert == null) {
            return new AlertClearResult(null, false, false, "窗口未关联任何告警，无需解除");
        }
        boolean removed = alert.getWindowKeys().remove(windowKeyEncoded);
        if (removed) {
            alert.setOccurrenceCount(Math.max(0, alert.getOccurrenceCount() - 1));
        }
        alert.setUpdatedAt(Instant.now());

        boolean untouchedAutoAlert = alert.getWindowKeys().isEmpty()
                && (AlertStatus.OPEN.name().equals(alert.getStatus())
                    || AlertStatus.SUPPRESSED.name().equals(alert.getStatus()))
                && transitionRepository.findByAlertIdOrderByIdAsc(alert.getId()).stream()
                        .allMatch(t -> "system".equals(t.getOperator()));
        if (alert.getWindowKeys().isEmpty() && untouchedAutoAlert) {
            long id = alert.getId();
            transitionRepository.deleteByAlertId(id);
            alertRepository.delete(alert);
            log.info("自愈: 窗口 {} 未达阈值，删除其误报告警 {} 及流转记录", windowKeyEncoded, id);
            return new AlertClearResult(id, true, false, "误报告警已删除（未被人工处置的纯自动告警）");
        }
        alertRepository.save(alert);
        boolean review = alert.getWindowKeys().isEmpty();
        log.info("自愈: 窗口 {} 解除关联，告警 {} 保留(occurrenceCount={}, status={}, 需人工复核={})",
                windowKeyEncoded, alert.getId(), alert.getOccurrenceCount(), alert.getStatus(), review);
        return new AlertClearResult(alert.getId(), false, review,
                review ? "告警已不关联任何窗口但已被人工处置，保留待人工复核" : "已从合并告警中移除该窗口");
    }

    /** 自愈解除告警关联的结果。 */
    public record AlertClearResult(Long alertId, boolean deleted, boolean needsManualReview, String note) {
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
}
