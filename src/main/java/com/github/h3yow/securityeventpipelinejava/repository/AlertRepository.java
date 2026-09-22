package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AlertRepository extends JpaRepository<AlertEntity, Long> {
    List<AlertEntity> findByRuleIdAndGroupKeyAndStatusInOrderByLastEventTimeDesc(
            long ruleId, String groupKey, List<String> statuses);
    List<AlertEntity> findAllByOrderByIdDesc();
}
