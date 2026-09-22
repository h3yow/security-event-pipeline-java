package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.AlertTransitionEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertTransitionRepository extends JpaRepository<AlertTransitionEntity, Long> {
    List<AlertTransitionEntity> findByAlertIdOrderByIdAsc(long alertId);
}
