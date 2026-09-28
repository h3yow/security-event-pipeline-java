package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface EventRepository extends JpaRepository<EventEntity, Long> {
    boolean existsByEventId(String eventId);

    /** 事件时间落在 [from, to) 的已受理事件（对账重算预期事件集用）。 */
    List<EventEntity> findByEventTimeGreaterThanEqualAndEventTimeLessThanOrderByEventTimeAscEventIdAsc(
            Instant from, Instant to);
}
