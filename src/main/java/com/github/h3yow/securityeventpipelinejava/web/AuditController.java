package com.github.h3yow.securityeventpipelinejava.web;

import com.github.h3yow.securityeventpipelinejava.entity.AlertTransitionEntity;
import com.github.h3yow.securityeventpipelinejava.entity.RejectedEventEntity;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.service.AlertService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 审计与可观测端点：拒绝记录、窗口计数依据、告警状态流转历史。 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final RejectedEventRepository rejectedEventRepository;
    private final WindowAggregateRepository windowAggregateRepository;
    private final AlertService alertService;

    public AuditController(RejectedEventRepository rejectedEventRepository,
                           WindowAggregateRepository windowAggregateRepository,
                           AlertService alertService) {
        this.rejectedEventRepository = rejectedEventRepository;
        this.windowAggregateRepository = windowAggregateRepository;
        this.alertService = alertService;
    }

    @GetMapping("/rejected")
    public List<RejectedEventEntity> rejected() {
        return rejectedEventRepository.findAllByOrderByIdDesc();
    }

    @GetMapping("/windows")
    public List<WindowAggregateEntity> windows() {
        return windowAggregateRepository.findAllByOrderByIdDesc();
    }

    @GetMapping("/alerts/{id}/transitions")
    public List<AlertTransitionEntity> transitions(@PathVariable long id) {
        return alertService.transitions(id);
    }
}
