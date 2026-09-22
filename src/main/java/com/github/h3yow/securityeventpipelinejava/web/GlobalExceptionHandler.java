package com.github.h3yow.securityeventpipelinejava.web;

import com.github.h3yow.securityeventpipelinejava.common.RejectReason;
import com.github.h3yow.securityeventpipelinejava.exception.AccessDeniedException;
import com.github.h3yow.securityeventpipelinejava.exception.PipelineException;
import com.github.h3yow.securityeventpipelinejava.exception.ResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(PipelineException.class)
    public ResponseEntity<Map<String, Object>> handle(PipelineException ex) {
        HttpStatus status = switch (ex.getReason()) {
            case DUPLICATE_EVENT -> HttpStatus.CONFLICT;
            case ACCESS_DENIED -> HttpStatus.FORBIDDEN;
            case ALERT_NOT_FOUND, RULE_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case ILLEGAL_STATE_TRANSITION -> HttpStatus.UNPROCESSABLE_ENTITY;
            default -> HttpStatus.BAD_REQUEST;
        };
        log.warn("请求被拒绝: reason={}, status={}, message={}", ex.getReason(), status, ex.getMessage());
        return ResponseEntity.status(status).body(body(ex.getReason(), ex.getMessage()));
    }

    /** 请求体 JSON 无法解析。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(body(RejectReason.ILLEGAL_FORMAT, "请求体不是合法 JSON: "
                        + ex.getMostSpecificCause().getMessage()));
    }

    /** 非法的 X-Operator-Role 枚举值等参数问题。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArg(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(body(RejectReason.ILLEGAL_FORMAT, ex.getMessage()));
    }

    private Map<String, Object> body(RejectReason reason, String message) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("accepted", false);
        b.put("reason", reason.name());
        b.put("message", message);
        return b;
    }
}
