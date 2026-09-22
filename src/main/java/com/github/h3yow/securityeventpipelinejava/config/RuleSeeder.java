package com.github.h3yow.securityeventpipelinejava.config;

import com.github.h3yow.securityeventpipelinejava.detection.DetectionRule;
import com.github.h3yow.securityeventpipelinejava.persistence.DetectionRuleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/** 启动时写入默认检测规则（幂等：已存在则跳过）。 */
@Component
public class RuleSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(RuleSeeder.class);

    private final DetectionRuleRepository ruleRepository;

    public RuleSeeder(DetectionRuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    @Override
    public void run(String... args) {
        seed(new DetectionRule("BRUTE_FORCE_LOGIN", 1, "LOGIN_FAIL",
                300, 3, 600, true));
        seed(new DetectionRule("CONNECTION_STORM", 1, "CONNECTION_DENIED",
                60, 5, 300, true));
    }

    private void seed(DetectionRule rule) {
        if (ruleRepository.findFirstByRuleIdAndEnabledTrueOrderByVersionDesc(rule.getRuleId()).isEmpty()) {
            ruleRepository.save(rule);
            log.info("seeded detection rule: {}@v{}", rule.getRuleId(), rule.getVersion());
        }
    }
}
