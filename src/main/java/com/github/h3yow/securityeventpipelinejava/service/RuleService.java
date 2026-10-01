package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.common.RuleAction;
import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.exception.PipelineException;
import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.web.RuleUpsertRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * 规则管理（版本化）。
 *
 * <p>同一 ruleCode 每次 upsert 都插入 version+1 的新行，旧版本保留：
 * 窗口聚合与告警均记录命中时的 ruleId/version 与规则快照，规则变更后历史判定依据仍可追溯。
 */
@Service
public class RuleService {

    private final RuleRepository ruleRepository;
    private final JsonService jsonService;
    private final WindowLockManager windowLockManager;
    private final TransactionTemplate transactionTemplate;

    public RuleService(RuleRepository ruleRepository, JsonService jsonService,
                       WindowLockManager windowLockManager,
                       PlatformTransactionManager transactionManager) {
        this.ruleRepository = ruleRepository;
        this.jsonService = jsonService;
        this.windowLockManager = windowLockManager;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    /** 当前生效的全部规则。 */
    public List<RuleEntity> activeRules() {
        return ruleRepository.findByEnabledTrue();
    }

    public List<RuleEntity> listRules() {
        return ruleRepository.findAll().stream()
                .sorted(Comparator.comparing(RuleEntity::getRuleCode)
                        .thenComparing(RuleEntity::getVersion))
                .toList();
    }

    public List<RuleEntity> history(String ruleCode) {
        return ruleRepository.findByRuleCodeOrderByVersionDesc(ruleCode);
    }

    /**
     * 创建新版本。在该 ruleCode 的规则版本锁内执行一个完整事务，锁覆盖到提交：
     * 与同 ruleCode 的事件接入互斥，{@code createdAt} 在锁内生成，
     * 保证接入/对账按 {@code [createdAt(v), createdAt(v+1))} 的版本归属在并发升级下确定一致。
     */
    public RuleEntity createOrUpdate(RuleUpsertRequest req) {
        validate(req);
        return windowLockManager.<RuleEntity>callLocked(req.ruleCode(),
                () -> transactionTemplate.execute(status -> persistNewVersion(req)));
    }

    /** 调用方必须已持有该 ruleCode 的规则锁且处于事务中。 */
    private RuleEntity persistNewVersion(RuleUpsertRequest req) {
        RuleEntity entity = new RuleEntity();
        entity.setRuleCode(req.ruleCode());
        entity.setName(req.name());
        Map<String, String> conditions = req.matchConditions() == null
                ? Map.of() : req.matchConditions();
        if (conditions.isEmpty()) {
            throw new PipelineException(RejectReason.MISSING_FIELD, "matchConditions 不能为空");
        }
        entity.setMatchConditionsJson(jsonService.write(conditions));
        entity.setGroupBy(req.groupBy() == null || req.groupBy().isBlank() ? "__GLOBAL__" : req.groupBy());
        entity.setWindowSeconds(req.windowSeconds());
        entity.setAllowedLatenessSeconds(req.allowedLatenessSeconds());
        entity.setThreshold(req.threshold());
        entity.setAction(req.action());
        entity.setDedupSeconds(req.dedupSeconds());
        entity.setEnabled(req.enabled() == null || req.enabled());
        entity.setCreatedAt(Instant.now());

        int nextVersion = ruleRepository.findByRuleCodeOrderByVersionDesc(req.ruleCode())
                .stream().findFirst().map(r -> r.getVersion() + 1).orElse(1);
        entity.setVersion(nextVersion);
        RuleEntity saved = ruleRepository.save(entity);

        // 旧版本标记为停用（行仍保留，供历史追溯）
        ruleRepository.findByRuleCodeOrderByVersionDesc(req.ruleCode()).stream()
                .filter(r -> r.getVersion() != nextVersion)
                .forEach(r -> {
                    r.setEnabled(false);
                    ruleRepository.save(r);
                });
        return saved;
    }

    private void validate(RuleUpsertRequest req) {
        if (req == null || req.ruleCode() == null || req.ruleCode().isBlank()) {
            throw new PipelineException(RejectReason.MISSING_FIELD, "缺少 ruleCode");
        }
        if (req.name() == null || req.name().isBlank()) {
            throw new PipelineException(RejectReason.MISSING_FIELD, "缺少 name");
        }
        requirePositive(req.windowSeconds(), "windowSeconds");
        requirePositive(req.allowedLatenessSeconds(), "allowedLatenessSeconds");
        if (req.threshold() == null || req.threshold() <= 0) {
            throw new PipelineException(RejectReason.ILLEGAL_FORMAT, "threshold 必须为正整数");
        }
        requirePositive(req.dedupSeconds(), "dedupSeconds");
        try {
            RuleAction.valueOf(req.action());
        } catch (Exception e) {
            throw new PipelineException(RejectReason.ILLEGAL_FORMAT,
                    "action 只能是 ALERT 或 SUPPRESS: " + req.action());
        }
    }

    private void requirePositive(Long v, String field) {
        if (v == null || v <= 0) {
            throw new PipelineException(RejectReason.ILLEGAL_FORMAT, field + " 必须为正数(秒)");
        }
    }
}
