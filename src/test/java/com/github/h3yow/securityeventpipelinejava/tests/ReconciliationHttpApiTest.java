package com.github.h3yow.securityeventpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.securityeventpipelinejava.entity.WindowAggregateEntity;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RepairAuditRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import com.github.h3yow.securityeventpipelinejava.web.EventIngestRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 对账查询与自愈的 HTTP 层测试。 */
@SpringBootTest
@AutoConfigureMockMvc
class ReconciliationHttpApiTest {

    private static final Logger log = LoggerFactory.getLogger(ReconciliationHttpApiTest.class);

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private IngestionService ingestionService;
    @Autowired private AlertRepository alertRepository;
    @Autowired private WindowAggregateRepository windowAggregateRepository;
    @Autowired private WindowEventRepository windowEventRepository;
    @Autowired private RejectedEventRepository rejectedEventRepository;
    @Autowired private EventRepository eventRepository;
    @Autowired private RepairAuditRepository repairAuditRepository;

    @BeforeEach
    void clean() {
        repairAuditRepository.deleteAllInBatch();
        alertRepository.deleteAllInBatch();
        windowAggregateRepository.deleteAllInBatch();
        windowEventRepository.deleteAllInBatch();
        rejectedEventRepository.deleteAllInBatch();
        eventRepository.deleteAllInBatch();
    }

    @Test
    void reconciliationAndRepairEndpointsWorkOverHttp() throws Exception {
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MINUTES).plusSeconds(10);
        for (int i = 1; i <= 3; i++) {
            EventIngestRequest req = new EventIngestRequest("AUTH", Map.of(
                    "eventId", "http-rc-" + i, "timestamp", ts.plusSeconds(i).toString(),
                    "username", "wendy", "result", "LOGIN_FAIL", "service", "ssh"));
            ingestionService.ingest(req);
        }
        log.info("[输入事件] http-rc-1..3 已受理");

        // 对账：一致窗口
        mockMvc.perform(get("/api/audit/windows/reconciliation")
                        .param("ruleCode", "AUTH_BRUTE_FORCE")
                        .param("groupKey", "wendy"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalWindows").value(1))
                .andExpect(jsonPath("$.inconsistentWindows").value(0))
                .andExpect(jsonPath("$.windows[0].consistent").value(true))
                .andExpect(jsonPath("$.windows[0].contributions.length()").value(3));

        // 制造漂移：count 改成 1
        WindowAggregateEntity agg = windowAggregateRepository.findAll().stream()
                .filter(a -> a.getGroupKey().equals("wendy")).findFirst().orElseThrow();
        agg.setCount(1);
        windowAggregateRepository.saveAndFlush(agg);

        mockMvc.perform(get("/api/audit/windows/reconciliation")
                        .param("ruleCode", "AUTH_BRUTE_FORCE")
                        .param("groupKey", "wendy"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.inconsistentWindows").value(1))
                .andExpect(jsonPath("$.windows[0].countMismatch").value(true));

        // 发起自愈
        String body = objectMapper.writeValueAsString(Map.of(
                "ruleCode", "AUTH_BRUTE_FORCE",
                "groupKey", "wendy",
                "onlyInconsistent", true,
                "triggerReason", "HTTP 对账发现 count 漂移"));
        mockMvc.perform(post("/api/audit/windows/repair")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .header("X-Operator", "ops-http").header("X-Operator-Role", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.changedWindows").value(1))
                .andExpect(jsonPath("$.scannedWindows").value(1))
                .andExpect(jsonPath("$.actions[0].countAfter").value(3));
        log.info("[判定依据] 修复已发起，count 1 -> 3");

        // 修复后再对账：一致；审计列表有记录
        mockMvc.perform(get("/api/audit/windows/reconciliation")
                        .param("ruleCode", "AUTH_BRUTE_FORCE").param("groupKey", "wendy"))
                .andExpect(jsonPath("$.inconsistentWindows").value(0));
        mockMvc.perform(get("/api/audit/windows/repair/audits"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].operator").value("ops-http"))
                .andExpect(jsonPath("$[0].changedWindows").value(1));
        log.info("[最终状态] 修复后对账一致，repair_audit 留有 1 条记录");

        // 未知规则版本 => 404 RULE_NOT_FOUND
        mockMvc.perform(get("/api/audit/windows/reconciliation")
                        .param("ruleCode", "AUTH_BRUTE_FORCE").param("ruleVersion", "99"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("RULE_NOT_FOUND"));
    }
}
