package com.github.h3yow.securityeventpipelinejava.persistence;

import com.github.h3yow.securityeventpipelinejava.detection.DetectionRule;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public interface DetectionRuleRepository extends JpaRepository<DetectionRule, Long> {

    /** 取某规则当前启用的最新版本。 */
    Optional<DetectionRule> findFirstByRuleIdAndEnabledTrueOrderByVersionDesc(String ruleId);

    List<DetectionRule> findByEnabledTrue();

    /** 每个 ruleId 只取最新启用版本：规则变更后旧版本不再参与评估。 */
    default List<DetectionRule> findLatestEnabledRules() {
        return findByEnabledTrue().stream()
                .collect(Collectors.groupingBy(DetectionRule::getRuleId,
                        Collectors.maxBy(Comparator.comparingInt(DetectionRule::getVersion))))
                .values().stream()
                .flatMap(Optional::stream)
                .toList();
    }
}
