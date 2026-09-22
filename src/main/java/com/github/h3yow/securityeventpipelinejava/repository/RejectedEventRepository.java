package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.RejectedEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RejectedEventRepository extends JpaRepository<RejectedEventEntity, Long> {
    List<RejectedEventEntity> findAllByOrderByIdDesc();
}
