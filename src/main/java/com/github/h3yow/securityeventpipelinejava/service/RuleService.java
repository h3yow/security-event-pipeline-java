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
 *
 * <h3>版本生效边界</h3>
 * 每次发布在 {@link RuleDeploymentLock} 的<b>升级独占区</b>内完成（含事务提交），
 * 新版本的 createdAt 由该协调器生成，严格晚于任何已完成受理的 ingestTime 与上一版本生效时刻。
 * 因此事件可按 {@code ingestTime ∈ [createdAt_v, createdAt_{v+1})} 无歧义地归属到受理时生效的版本。
 */
@Service
public class RuleService {

    /** 一个规则版本的生效区间：[effectiveFrom, effectiveTo)，effectiveTo 为 null 表示至今仍生效。 */
    public record VersionInterval(long ruleId, int version,
                                  Instant effectiveFrom, Instant effectiveTo) {
        /** 给定受理时刻是否落在该版本生效区间内。 */
        public boolean inEffectAt(Instant ingestTime) {
            return !ingestTime.isBefore(effectiveFrom)
                    && (effectiveTo == null || ingestTime.isBefore(effectiveTo));
        }
    }

    private final RuleRepository ruleRepository;
    private final JsonService jsonService;
    private final RuleDeploymentLock deploymentLock;
    private final TransactionTemplate transactionTemplate;

    public RuleService(RuleRepository ruleRepository, JsonService jsonService,
                       RuleDeploymentLock deploymentLock,
                       PlatformTransactionManager transactionManager) {
        this.ruleRepository = ruleRepository;
        this.jsonService = jsonService;
        this.deploymentLock = deploymentLock;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    /** 当前生效的全部规则。调用方在受理读视图内使用。 */
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

    /** 某规则全部版本（按版本升序）的生效区间，供对账/自愈把事件归属到受理时的版本。 */
    public List<VersionInterval> versionIntervals(String ruleCode) {
        List<RuleEntity> asc = ruleRepository.findByRuleCodeOrderByVersionDesc(ruleCode).stream()
                .sorted(Comparator.comparingInt(RuleEntity::getVersion))
                .toList();
        return buildIntervals(asc);
    }

    private static List<VersionInterval> buildIntervals(List<RuleEntity> asc) {
        return java.util.stream.IntStream.range(0, asc.size()).mapToObj(i -> {
            RuleEntity r = asc.get(i);
            Instant to = i + 1 < asc.size() ? asc.get(i + 1).getCreatedAt() : null;
            return new VersionInterval(r.getId(), r.getVersion(), r.getCreatedAt(), to);
        }).toList();
    }

    /**
     * 发布新版本：校验后在规则部署升级锁内执行单事务（插入新版本 + 停用旧版本）。
     * 事务在锁内提交，期间到达的受理会等升级完成后看到新版本。
     */
    public RuleEntity createOrUpdate(RuleUpsertRequest req) {
        validate(req);
        return deploymentLock.upgrade(() -> transactionTemplate.execute(status -> {
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
            // 生效时刻由部署协调器生成，严格晚于所有已完成受理（边界归属唯一）
            entity.setCreatedAt(deploymentLock.nextVersionCreatedAt());

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
        }));
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
