package com.github.h3yow.securityeventpipelinejava.web;

import java.util.Map;

public record RuleUpsertRequest(
        String ruleCode,
        String name,
        Map<String, String> matchConditions,
        String groupBy,
        Long windowSeconds,
        Long allowedLatenessSeconds,
        Integer threshold,
        String action,
        Long dedupSeconds,
        Boolean enabled
) {
}
