package com.github.h3yow.securityeventpipelinejava.ingest;

import com.github.h3yow.securityeventpipelinejava.alert.AlertService;
import com.github.h3yow.securityeventpipelinejava.detection.DetectionRule;
import com.github.h3yow.securityeventpipelinejava.detection.RuleEngine;
import com.github.h3yow.securityeventpipelinejava.detection.WindowEvaluation;
import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.model.NormalizedEvent;
import com.github.h3yow.securityeventpipelinejava.model.RejectedEvent;
import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;
import com.github.h3yow.securityeventpipelinejava.persistence.DetectionRuleRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.NormalizedEventRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.RejectedEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * 接入服务：归一化 → 迟到检查 → 幂等落库 → 触发检测。
 * 任何失败都记录 RejectedEvent，绝不静默丢弃；
 * eventId 唯一约束保证并发重试/重复提交只处理一次。
 */
@Service
public class IngestService {

    private static final Logger log = LoggerFactory.getLogger(IngestService.class);

    private final Map<EventSource, LogNormalizer> normalizers = new EnumMap<>(EventSource.class);
    private final NormalizedEventRepository eventRepository;
    private final RejectedEventRepository rejectedEventRepository;
    private final DetectionRuleRepository ruleRepository;
    private final RuleEngine ruleEngine;
    private final AlertService alertService;

    public IngestService(List<LogNormalizer> normalizerList,
                         NormalizedEventRepository eventRepository,
                         RejectedEventRepository rejectedEventRepository,
                         DetectionRuleRepository ruleRepository,
                         RuleEngine ruleEngine,
                         AlertService alertService) {
        for (LogNormalizer n : normalizerList) {
            normalizers.put(n.supportedSource(), n);
        }
        this.eventRepository = eventRepository;
        this.rejectedEventRepository = rejectedEventRepository;
        this.ruleRepository = ruleRepository;
        this.ruleEngine = ruleEngine;
        this.alertService = alertService;
    }

    /**
     * 处理一条原始日志。同一 eventId 重复提交（含并发）只处理一次。
     */
    public IngestResult ingest(RawLogRequest request) {
        String eventId = request.eventId();
        // 1. 请求级校验
        if (eventId == null || eventId.isBlank()) {
            return reject(null, request, RejectionReason.MISSING_FIELD, "eventId is missing");
        }
        if (request.source() == null) {
            return reject(eventId, request, RejectionReason.MISSING_FIELD, "source is missing");
        }
        if (request.payload() == null || request.payload().isBlank()) {
            return reject(eventId, request, RejectionReason.MISSING_FIELD, "payload is missing");
        }

        // 2. 归一化
        NormalizedEvent event;
        try {
            event = normalizers.get(request.source()).normalize(eventId, request.payload());
        } catch (NormalizationException e) {
            return reject(eventId, request, e.getReason(), e.getMessage());
        }

        // 3. 迟到检查：事件时间早于 水位线-最大允许迟到 的记录被拒绝（可区分原因）
        Instant watermark = eventRepository.maxEventTime();
        if (watermark != null) {
            long maxLateness = ruleRepository.findLatestEnabledRules().stream()
                    .mapToLong(DetectionRule::getMaxLatenessSeconds)
                    .max().orElse(0);
            Instant tooLateBefore = watermark.minusSeconds(maxLateness);
            if (event.getEventTime().isBefore(tooLateBefore)) {
                return reject(eventId, request, RejectionReason.TOO_LATE,
                        "eventTime " + event.getEventTime() + " is before watermark " + watermark
                                + " minus maxLateness " + maxLateness + "s");
            }
        }

        // 4. 幂等落库：唯一约束兜底并发重复
        try {
            eventRepository.saveAndFlush(event);
        } catch (DataIntegrityViolationException e) {
            log.info("duplicate event ignored: eventId={}", eventId);
            return IngestResult.rejected(eventId, RejectionReason.DUPLICATE,
                    "eventId already processed");
        }

        // 5. 触发检测并生成/合并告警
        List<WindowEvaluation> evaluations = ruleEngine.evaluate(event);
        for (WindowEvaluation eval : evaluations) {
            if (eval.triggered()) {
                alertService.raiseOrMerge(eval);
            }
        }
        log.info("ingested event: eventId={} source={} action={} eventTime={} triggeredRules={}",
                eventId, event.getSource(), event.getAction(), event.getEventTime(),
                evaluations.stream().filter(WindowEvaluation::triggered).count());
        return IngestResult.accepted(eventId);
    }

    private IngestResult reject(String eventId, RawLogRequest request,
                                RejectionReason reason, String detail) {
        rejectedEventRepository.save(new RejectedEvent(eventId,
                request.source() == null ? null : request.source().name(),
                reason, detail, request.payload(), Instant.now()));
        log.warn("rejected event: eventId={} reason={} detail={}", eventId, reason, detail);
        return IngestResult.rejected(eventId, reason, detail);
    }
}
