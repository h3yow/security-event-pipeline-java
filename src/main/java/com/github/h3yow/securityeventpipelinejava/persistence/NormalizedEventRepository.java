package com.github.h3yow.securityeventpipelinejava.persistence;

import com.github.h3yow.securityeventpipelinejava.model.NormalizedEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface NormalizedEventRepository extends JpaRepository<NormalizedEvent, Long> {

    boolean existsByEventId(String eventId);

    Optional<NormalizedEvent> findByEventId(String eventId);

    /** 查询某分组键在事件时间窗口内、指定动作的事件（按事件时间升序），用于窗口计数。 */
    @Query("select e from NormalizedEvent e where e.groupKey = :groupKey and e.action = :action "
            + "and e.eventTime >= :from and e.eventTime <= :to order by e.eventTime asc")
    List<NormalizedEvent> findWindowEvents(@Param("groupKey") String groupKey,
                                           @Param("action") String action,
                                           @Param("from") Instant from,
                                           @Param("to") Instant to);

    /** 当前水位线：已见事件的最大事件时间。 */
    @Query("select max(e.eventTime) from NormalizedEvent e")
    Instant maxEventTime();
}
