package com.github.h3yow.securityeventpipelinejava.web;

import com.github.h3yow.securityeventpipelinejava.domain.healing.HealOutcome;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.ReconciliationQuery;
import com.github.h3yow.securityeventpipelinejava.domain.reconciliation.WindowReconciliationResult;
import com.github.h3yow.securityeventpipelinejava.entity.WindowHealAuditEntity;
import com.github.h3yow.securityeventpipelinejava.service.HealingService;
import com.github.h3yow.securityeventpipelinejava.service.ReconciliationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 窗口对账查询与自愈端点（骨架）。
 */
@RestController
@RequestMapping("/api/audit/windows")
public class ReconciliationController {

    private final ReconciliationService reconciliationService;
    private final HealingService healingService;

    public ReconciliationController(ReconciliationService reconciliationService,
                                    HealingService healingService) {
        this.reconciliationService = reconciliationService;
        this.healingService = healingService;
    }

    @GetMapping("/reconcile")
    public List<WindowReconciliationResult> reconcile(
            @RequestParam(required = false) String ruleCode,
            @RequestParam(required = false) Integer version,
            @RequestParam(required = false) String groupKey,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        return reconciliationService.reconcile(
                new ReconciliationQuery(ruleCode, version, groupKey, from, to));
    }

    @PostMapping("/heal")
    public HealOutcome heal(@RequestHeader(value = "X-Operator", required = false) String operator,
                            @RequestBody(required = false) HealRequest request) {
        return healingService.heal(operator, request);
    }

    @GetMapping("/heals")
    public List<WindowHealAuditEntity> heals() {
        return healingService.auditTrail();
    }
}
