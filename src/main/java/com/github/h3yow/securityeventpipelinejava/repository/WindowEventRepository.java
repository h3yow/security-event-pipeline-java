package com.github.h3yow.securityeventpipelinejava.repository;

import com.github.h3yow.securityeventpipelinejava.entity.WindowEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface WindowEventRepository extends JpaRepository<WindowEventEntity, Long> {
    boolean existsByRuleIdAndWindowKeyAndEventId(long ruleId, String windowKey, String eventId);

    /** 某窗口实际纳入的全部去重事件，按 eventId 升序（对账结果稳定）。 */
    List<WindowEventEntity> findByRuleIdAndWindowKeyOrderByEventIdAsc(long ruleId, String windowKey);

    /** 自愈：移除某窗口内不再成立的关联行（孤儿关联）。 */
    void deleteByRuleIdAndWindowKeyAndEventId(long ruleId, String windowKey, String eventId);

    void deleteAllInBatch();
}
