package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface WindowAggregateRepository extends JpaRepository<WindowAggregateEntity, Long> {
    Optional<WindowAggregateEntity> findByRuleIdAndVersionAndGroupKeyAndWindowStart(
            long ruleId, int version, String groupKey, long windowStart);

    List<WindowAggregateEntity> findAllByOrderByIdDesc();
}
