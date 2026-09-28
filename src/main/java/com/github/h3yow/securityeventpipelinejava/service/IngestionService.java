package com.github.h3yow.securityeventpipelinejava.service;

import com.github.h3yow.securityeventpipelinejava.domain.IngestResult;
import com.github.h3yow.securityeventpipelinejava.domain.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.domain.WindowTarget;
import com.github.h3yow.securityeventpipelinejava.entity.EventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RejectedEventEntity;
import com.github.h3yow.securityeventpipelinejava.exception.DuplicateEventException;
import com.github.h3yow.securityeventpipelinejava.exception.ValidationException;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 事件接入服务。
 *
 * <p>幂等保证（双层）：
 * <ol>
 *   <li>JVM 内 eventId 分段锁(striped)：并发/重试的同一事件串行化，只有第一个进入处理路径；</li>
 *   <li>accepted_event.event_id 数据库唯一约束：进程级兜底，重复插入直接失败。</li>
 * </ol>
 * 校验失败不静默丢弃：归一化阶段拒绝直接写 rejected_event；检测阶段拒绝(如窗口过期)
 * 在独立留痕事务中记录，再回滚事件事务。
 */
@Service
public class IngestionService {

    private static final Logger log = LoggerFactory.getLogger(IngestionService.class);

    /** 64 段锁，对相同 eventId 互斥、不同 eventId 并行（避免引入额外依赖）。 */
    private final Lock[] eventLocks = createStripedLocks(64);

    private final Normalizer normalizer;
    private final EventRepository eventRepository;
    private final RejectedEventRepository rejectedEventRepository;
    private final DetectionService detectionService;
    private final WindowLockManager windowLockManager;
    private final JsonService jsonService;

    public IngestionService(Normalizer normalizer,
                            EventRepository eventRepository,
                            RejectedEventRepository rejectedEventRepository,
                            DetectionService detectionService,
                            WindowLockManager windowLockManager,
                            JsonService jsonService) {
        this.normalizer = normalizer;
        this.eventRepository = eventRepository;
        this.rejectedEventRepository = rejectedEventRepository;
        this.detectionService = detectionService;
        this.windowLockManager = windowLockManager;
        this.jsonService = jsonService;
    }

    private static Lock[] createStripedLocks(int stripes) {
        Lock[] locks = new Lock[stripes];
        for (int i = 0; i < stripes; i++) {
            locks[i] = new ReentrantLock();
        }
        return locks;
    }

    private Lock lockFor(String eventId) {
        return eventLocks[Math.floorMod(eventId.hashCode(), eventLocks.length)];
    }

    public IngestResult ingest(EventIngestRequest request) {
        String rawJson = jsonService.write(request == null ? "null" : request);
        NormalizedEvent event;
        try {
            event = normalizer.normalize(request, rawJson);
        } catch (ValidationException ex) {
            String eventId = extractEventId(request);
            recordRejection(eventId, request == null ? null : request.source(),
                    ex.getReason().name(), ex.getMessage(), rawJson);
            return IngestResult.rejected(eventId, ex.getReason().name(), ex.getMessage());
        }

        String eventId = event.eventId();
        Lock eventLock = lockFor(eventId);
        eventLock.lock();
        try {
            if (eventRepository.existsByEventId(eventId)) {
                log.warn("重复提交被拒绝: eventId={}", eventId);
                throw new DuplicateEventException(eventId);
            }

            // 纯计算：匹配规则、对齐窗口、迟到判定（不持数据库连接/事务）
            List<WindowTarget> targets;
            try {
                targets = detectionService.resolveTargets(event);
            } catch (ValidationException lateReject) {
                // 窗口已过期：独立事务留痕，事件不落库，但拒绝不静默
                recordRejection(eventId, event.source().name(),
                        lateReject.getReason().name(), lateReject.getMessage(), rawJson);
                return IngestResult.rejected(eventId,
                        lateReject.getReason().name(), lateReject.getMessage());
            }

            // 事务外按窗口键排序获取全部窗口锁：同窗口并发读-改-写串行化，且杜绝多窗口死锁。
            // 与事件级锁配合：相同事件重试仍串行、只算一次；不同事件对同窗口排队、各自计一次。
            List<Lock> heldLocks = new java.util.ArrayList<>(targets.size());
            try {
                for (WindowTarget t : targets) {
                    Lock l = windowLockManager.lockFor(t.key().encode());
                    l.lock();
                    heldLocks.add(l);
                }
                List<Long> alertIds;
                try {
                    // 单一事务：事件落库 + 窗口计数 + 建警；任一步异常整体回滚
                    alertIds = detectionService.processEvent(event, targets);
                } catch (DuplicateEventException dup) {
                    // 极端并发下由 event_id 唯一约束兜底：重新抛出，由全局处理器归类为 409
                    throw dup;
                }
                log.info("事件处理完成: eventId={}, 触发/关联告警IDs={}", eventId, alertIds);
                return IngestResult.ok(eventId, alertIds);
            } finally {
                // 逆序释放
                for (int i = heldLocks.size() - 1; i >= 0; i--) {
                    heldLocks.get(i).unlock();
                }
            }
        } finally {
            eventLock.unlock();
        }
    }

    @Transactional
    public void recordRejection(String eventId, String source, String reason,
                                String detail, String rawJson) {
        RejectedEventEntity rejected = new RejectedEventEntity();
        rejected.setEventId(eventId);
        rejected.setSource(source);
        rejected.setReason(reason);
        rejected.setDetail(detail);
        rejected.setRawPayload(rawJson);
        rejected.setRejectedAt(Instant.now());
        rejectedEventRepository.save(rejected);
    }

    private String extractEventId(EventIngestRequest request) {
        if (request != null && request.payload() != null) {
            Object id = request.payload().get("eventId");
            return id == null ? null : String.valueOf(id);
        }
        return null;
    }
}
