package com.github.h3yow.securityeventpipelinejava.web;

import com.github.h3yow.securityeventpipelinejava.domain.recon.RepairResult;
import com.github.h3yow.securityeventpipelinejava.domain.recon.WindowReconciliationReport;
import com.github.h3yow.securityeventpipelinejava.entity.RepairAuditEntity;
import com.github.h3yow.securityeventpipelinejava.repository.RepairAuditRepository;
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
 * 面向运维的窗口对账与自愈端点（骨架，实现随服务填充）。
 */
@RestController
@RequestMapping("/api/audit/windows")
public class ReconciliationController {

    private final ReconciliationService reconciliationService;
    private final RepairAuditRepository repairAuditRepository;

    public ReconciliationController(ReconciliationService reconciliationService,
                                    RepairAuditRepository repairAuditRepository) {
        this.reconciliationService = reconciliationService;
        this.repairAuditRepository = repairAuditRepository;
    }

    /** 窗口对账查询：按规则(含版本)/分组/窗口区间查看判定实际纳入情况与差异。 */
    @GetMapping("/reconciliation")
    public WindowReconciliationReport reconcile(
            @RequestParam String ruleCode,
            @RequestParam(required = false) Integer ruleVersion,
            @RequestParam(required = false) String groupKey,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {
        return reconciliationService.reconcile(ruleCode, ruleVersion, groupKey, from, to);
    }

    /** 对指定范围内的窗口发起一次自愈（可重复、可并发，结果幂等收敛）。 */
    @PostMapping("/repair")
    public RepairResult repair(@RequestBody(required = false) WindowRepairRequest request,
                               @RequestHeader(value = "X-Operator", required = false) String operator,
                               @RequestHeader(value = "X-Operator-Role", required = false) String operatorRole) {
        return reconciliationService.repair(request, operator, operatorRole);
    }

    /** 自愈审计记录列表（何时、因何、处理了哪些窗口）。 */
    @GetMapping("/repair/audits")
    public List<RepairAuditEntity> repairAudits() {
        return repairAuditRepository.findAllByOrderByIdDesc();
    }
}
