package com.github.h3yow.securityeventpipelinejava.config;

import com.github.h3yow.securityeventpipelinejava.repository.RuleRepository;
import com.github.h3yow.securityeventpipelinejava.service.JsonService;
import com.github.h3yow.securityeventpipelinejava.service.RuleService;
import com.github.h3yow.securityeventpipelinejava.web.RuleUpsertRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

/** 首次启动时写入演示规则（库中已有规则则跳过）。 */
@Configuration
public class DataSeeder {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    @Bean
    public ApplicationRunner seedRules(RuleService ruleService, RuleRepository ruleRepository,
                                       JsonService jsonService) {
        return args -> {
            if (ruleRepository.count() > 0) {
                return;
            }
            ruleService.createOrUpdate(new RuleUpsertRequest(
                    "AUTH_BRUTE_FORCE", "认证暴力破解",
                    Map.of("action", "LOGIN_FAIL"),
                    "actor", 60L, 120L, 3, "ALERT", 180L, true));
            ruleService.createOrUpdate(new RuleUpsertRequest(
                    "FW_PORT_SCAN", "防火墙端口扫描",
                    Map.of("action", "DENY"),
                    "sourceIp", 60L, 120L, 4, "ALERT", 180L, true));
            ruleService.createOrUpdate(new RuleUpsertRequest(
                    "FW_NOISY_DENY", "防火墙高频拦截(抑制演示)",
                    Map.of("action", "DENY"),
                    "sourceIp", 60L, 120L, 10, "SUPPRESS", 180L, true));
            log.info("演示规则种子数据已写入: AUTH_BRUTE_FORCE / FW_PORT_SCAN / FW_NOISY_DENY");
        };
    }
}
