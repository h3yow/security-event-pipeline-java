package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.AlertTransitionEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertTransitionRepository extends JpaRepository<AlertTransitionEntity, Long> {
    List<AlertTransitionEntity> findByAlertIdOrderByIdAsc(long alertId);

    /** 自愈删除误报告警时，连带清理其流转记录（修复审计另行留痕）。 */
    void deleteByAlertId(long alertId);
}
