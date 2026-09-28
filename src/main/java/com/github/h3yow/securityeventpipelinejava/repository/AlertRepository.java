package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface AlertRepository extends JpaRepository<AlertEntity, Long> {
    List<AlertEntity> findByRuleIdAndGroupKeyAndStatusInOrderByLastEventTimeDesc(
            long ruleId, String groupKey, List<String> statuses);
    List<AlertEntity> findAllByOrderByIdDesc();

    /** 告警窗口关联表中包含指定窗口键的告警（element-collection 表 alert_window）。 */
    @Query(value = "SELECT DISTINCT a FROM AlertEntity a JOIN a.windowKeys w WHERE w = :windowKey")
    List<AlertEntity> findByWindowKey(@Param("windowKey") String windowKey);
}
