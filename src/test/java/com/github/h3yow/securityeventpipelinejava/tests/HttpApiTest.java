package com.github.h3yow.securityeventpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.securityeventpipelinejava.entity.AlertEntity;
import com.github.h3yow.securityeventpipelinejava.repository.AlertRepository;
import com.github.h3yow.securityeventpipelinejava.repository.EventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.RejectedEventRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowAggregateRepository;
import com.github.h3yow.securityeventpipelinejava.repository.WindowEventRepository;
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
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 层测试：异常被正确归类为状态码与可区分原因，响应体结构正确。
 */
@SpringBootTest
@AutoConfigureMockMvc
class HttpApiTest {

    private static final Logger log = LoggerFactory.getLogger(HttpApiTest.class);

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private AlertRepository alertRepository;
    @Autowired private WindowAggregateRepository windowAggregateRepository;
    @Autowired private WindowEventRepository windowEventRepository;
    @Autowired private RejectedEventRepository rejectedEventRepository;
    @Autowired private EventRepository eventRepository;

    @BeforeEach
    void clean() {
        alertRepository.deleteAllInBatch();
        windowAggregateRepository.deleteAllInBatch();
        windowEventRepository.deleteAllInBatch();
        rejectedEventRepository.deleteAllInBatch();
        eventRepository.deleteAllInBatch();
    }

    private String authEvent(String id, Instant ts, String user, String result) throws Exception {
        return objectMapper.writeValueAsString(Map.of(
                "source", "AUTH",
                "payload", Map.of("eventId", id, "timestamp", ts.toString(),
                        "username", user, "result", result, "service", "ssh")));
    }

    @Test
    void httpStatusAndReasonsAreClassifiedCorrectly() throws Exception {
        Instant ts = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES);

        // 缺字段 => 400 MISSING_FIELD
        log.info("[输入事件] 缺少 username 的 AUTH 事件");
        String missing = objectMapper.writeValueAsString(Map.of("source", "AUTH",
                "payload", Map.of("eventId", "h-bad", "timestamp", ts.plusSeconds(5).toString(),
                        "result", "LOGIN_FAIL", "service", "ssh")));
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON).content(missing))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.rejection.reason").value("MISSING_FIELD"));

        // 坏 JSON => 400 ILLEGAL_FORMAT
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON).content("{not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("ILLEGAL_FORMAT"));

        // 正常 3 连 => 第三次 200 且 alertIds 非空
        for (int i = 1; i <= 3; i++) {
            mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON)
                    .content(authEvent("h-ok-" + i, ts.plusSeconds(10 + i), "heidi", "LOGIN_FAIL")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accepted").value(true));
        }
        AlertEntity alert = alertRepository.findAll().stream().findFirst().orElseThrow();
        log.info("[最终状态] 建警 id={} status={}", alert.getId(), alert.getStatus());

        // 重复 => 409 DUPLICATE_EVENT
        mockMvc.perform(post("/api/events").contentType(MediaType.APPLICATION_JSON)
                .content(authEvent("h-ok-1", ts.plusSeconds(11), "heidi", "LOGIN_FAIL")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("DUPLICATE_EVENT"));

        // VIEWER 流转 => 403 ACCESS_DENIED
        mockMvc.perform(post("/api/alerts/" + alert.getId() + "/transition")
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Operator-Role", "VIEWER")
                .content("{\"targetStatus\":\"RESOLVED\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ACCESS_DENIED"));

        // 先 ACK + RESOLVED，再回退 => 422 ILLEGAL_STATE_TRANSITION
        mockMvc.perform(post("/api/alerts/" + alert.getId() + "/transition")
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Operator-Role", "ANALYST")
                .content("{\"targetStatus\":\"ACKNOWLEDGED\"}")).andExpect(status().isOk());
        mockMvc.perform(post("/api/alerts/" + alert.getId() + "/transition")
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Operator-Role", "ADMIN")
                .content("{\"targetStatus\":\"RESOLVED\"}")).andExpect(status().isOk());
        mockMvc.perform(post("/api/alerts/" + alert.getId() + "/transition")
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Operator-Role", "ADMIN")
                .content("{\"targetStatus\":\"OPEN\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.reason").value("ILLEGAL_STATE_TRANSITION"));

        // 不存在的告警 => 404 ALERT_NOT_FOUND
        mockMvc.perform(post("/api/alerts/999999/transition")
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Operator-Role", "ADMIN")
                .content("{\"targetStatus\":\"OPEN\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("ALERT_NOT_FOUND"));

        // 审计端点可查
        mockMvc.perform(get("/api/audit/rejected")).andExpect(status().isOk());
        log.info("[判定依据] 状态码归类: 400 MISSING_FIELD / 409 DUPLICATE_EVENT / 403 ACCESS_DENIED / 422 ILLEGAL_STATE_TRANSITION / 404 ALERT_NOT_FOUND 全部验证通过");
    }
}
