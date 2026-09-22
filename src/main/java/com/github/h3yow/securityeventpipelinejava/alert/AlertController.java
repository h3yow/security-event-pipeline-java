package com.github.h3yow.securityeventpipelinejava.alert;

import com.github.h3yow.securityeventpipelinejava.persistence.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.persistence.AlertTransitionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/** 告警查询与状态流转 API。 */
@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService alertService;
    private final AlertRepository alertRepository;
    private final AlertTransitionRepository transitionRepository;

    public AlertController(AlertService alertService,
                           AlertRepository alertRepository,
                           AlertTransitionRepository transitionRepository) {
        this.alertService = alertService;
        this.alertRepository = alertRepository;
        this.transitionRepository = transitionRepository;
    }

    @GetMapping
    public List<Alert> list() {
        return alertRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Alert> get(@PathVariable long id) {
        return alertRepository.findById(id).map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /** 告警的流转审计历史。 */
    @GetMapping("/{id}/transitions")
    public List<AlertTransition> transitions(@PathVariable long id) {
        return transitionRepository.findByAlertIdOrderByOccurredAtAsc(id);
    }

    /**
     * 状态流转。请求头 X-Role 携带操作者角色（ANALYST/ADMIN）。
     * 非法流转 → 409；越权 → 403；告警不存在 → 404。
     */
    @PostMapping("/{id}/transition")
    public Alert transition(@PathVariable long id,
                            @RequestBody TransitionRequest body,
                            @RequestHeader(value = "X-Role", required = false) String role) {
        return alertService.transition(id, body.target(), role, body.note());
    }

    public record TransitionRequest(AlertStatus target, String note) {
    }

    @ExceptionHandler(AlertTransitionException.class)
    public ResponseEntity<Map<String, String>> handleTransitionError(AlertTransitionException e) {
        HttpStatus status = switch (e.getKind()) {
            case ALERT_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case FORBIDDEN_ROLE -> HttpStatus.FORBIDDEN;
            case ILLEGAL_TRANSITION -> HttpStatus.CONFLICT;
        };
        return ResponseEntity.status(status)
                .body(Map.of("kind", e.getKind().name(), "reason", e.getMessage()));
    }
}
