package com.github.h3yow.securityeventpipelinejava.persistence;

import com.github.h3yow.securityeventpipelinejava.model.RejectedEvent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RejectedEventRepository extends JpaRepository<RejectedEvent, Long> {
}
