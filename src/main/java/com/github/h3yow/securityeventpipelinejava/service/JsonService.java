package com.github.h3yow.securityeventpipelinejava.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.exception.PipelineException;
import org.springframework.stereotype.Component;

import java.util.Map;

/** JSON 读写封装，基于 Jackson。 */
@Component
public class JsonService {
    private final ObjectMapper objectMapper;

    public JsonService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String write(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new PipelineException(RejectReason.INTERNAL_ERROR, "JSON 序列化失败: " + e.getMessage());
        }
    }

    public Map<String, String> readStringMap(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<Map<String, String>>() {
            });
        } catch (Exception e) {
            throw new PipelineException(RejectReason.INTERNAL_ERROR, "JSON 反序列化失败: " + e.getMessage());
        }
    }

    public <T> T read(String json, Class<T> type) {
        try {
            return objectMapper.readValue(json, type);
        } catch (Exception e) {
            throw new PipelineException(RejectReason.INTERNAL_ERROR, "JSON 反序列化失败: " + e.getMessage());
        }
    }
}
