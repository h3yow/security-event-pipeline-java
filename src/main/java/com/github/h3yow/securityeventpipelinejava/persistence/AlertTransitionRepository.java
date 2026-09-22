package com.github.h3yow.securityeventpipelinejava.persistence;

import com.github.h3yow.securityeventpipelinejava.alert.AlertTransition;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertTransitionRepository extends JpaRepository<AlertTransition, Long> {

    List<AlertTransition> findByAlertIdOrderByOccurredAtAsc(Long alertId);
}
