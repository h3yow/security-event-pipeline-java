package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RuleRepository extends JpaRepository<RuleEntity, Long> {
    List<RuleEntity> findByEnabledTrue();
    Optional<RuleEntity> findByRuleCodeAndEnabledTrue(String ruleCode);
    List<RuleEntity> findByRuleCodeOrderByVersionDesc(String ruleCode);
    boolean existsByRuleCodeAndVersion(String ruleCode, int version);
}
