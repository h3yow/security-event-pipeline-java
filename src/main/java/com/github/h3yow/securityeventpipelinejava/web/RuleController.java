package com.github.h3yow.securityeventpipelinejava.web;

import com.github.h3yow.securityeventpipelinejava.entity.RuleEntity;
import com.github.h3yow.securityeventpipelinejava.service.RuleService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/rules")
public class RuleController {
    private final RuleService ruleService;

    public RuleController(RuleService ruleService) {
        this.ruleService = ruleService;
    }

    @GetMapping
    public List<RuleEntity> directly() {
        return ruleService.listRules();
    }

    @GetMapping("/{ruleCode}/history")
    public List<RuleEntity> history(@PathVariable String ruleCode) {
        return ruleService.history(ruleCode);
    }

    @PostMapping
    public RuleEntity upsert(@RequestBody RuleUpsertRequest request) {
        return ruleService.createOrUpdate(request);
    }
}
