package com.github.h3yow.securityeventpipelinejava.persistence;

import com.github.h3yow.securityeventpipelinejava.alert.Alert;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    /** 按去重指纹查找（ruleId + groupKey + 窗口桶）。 */
    Optional<Alert> findByFingerprint(String fingerprint);
}
