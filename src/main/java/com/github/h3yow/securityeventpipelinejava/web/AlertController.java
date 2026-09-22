package com.github.h3yow.securityeventpipelinejava.web;

import com.github.h3yow.securityeventpipelinejava.common.OperatorRole;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.service.AlertService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {
    private final AlertService alertService;

    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    @GetMapping
    public List<AlertEntity> list() {
        return alertService.listAlerts();
    }

    @PostMapping("/{id}/transition")
    public AlertEntity transition(@PathVariable long id,
                                  @RequestBody AlertActionRequest request,
                                  @RequestHeader(value = "X-Operator", required = false) String operator,
                                  @RequestHeader(value = "X-Operator-Role", required = false) String role) {
        return alertService.transition(id, request.targetStatus(), operator,
                role == null ? null : OperatorRole.valueOf(role), request.note());
    }
}
