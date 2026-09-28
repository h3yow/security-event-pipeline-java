package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface WindowEventRepository extends JpaRepository<WindowEventEntity, Long> {
    boolean existsByRuleIdAndWindowKeyAndEventId(long ruleId, String windowKey, String eventId);
    List<WindowEventEntity> findByWindowKeyOrderByEventIdAsc(String windowKey);
    void deleteByWindowKeyAndEventIdIn(String windowKey, List<String> eventIds);
    void deleteAllInBatch();
}
