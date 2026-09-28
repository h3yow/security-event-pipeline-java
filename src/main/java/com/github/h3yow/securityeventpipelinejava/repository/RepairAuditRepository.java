package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.RepairAuditEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RepairAuditRepository extends JpaRepository<RepairAuditEntity, Long> {
    List<RepairAuditEntity> findAllByOrderByIdDesc();
}
