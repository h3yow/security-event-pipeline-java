package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.WindowHealAuditEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface WindowHealAuditRepository extends JpaRepository<WindowHealAuditEntity, Long> {
    List<WindowHealAuditEntity> findAllByOrderByIdDesc();
}
