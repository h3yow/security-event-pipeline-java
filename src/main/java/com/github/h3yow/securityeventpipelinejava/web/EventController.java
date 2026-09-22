package com.github.h3yow.securityeventpipelinejava.web;

import com.github.h3yow.securityeventpipelinejava.domain.IngestResult;
import com.github.h3yow.securityeventpipelinejava.service.IngestionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/events")
public class EventController {
    private final IngestionService ingestionService;

    public EventController(IngestionService ingestionService) {
        this.ingestionService = ingestionService;
    }

    @PostMapping
    public ResponseEntity<IngestResult> ingest(@RequestBody EventIngestRequest request) {
        IngestResult result = ingestionService.ingest(request);
        // 接受返回 200；记录被拒绝（字段/时间戳/窗口过期等）返回 400，响应体仍含可区分原因；
        // 重复事件由异常处理器返回 409。
        return ResponseEntity.status(result.accepted() ? HttpStatus.OK : HttpStatus.BAD_REQUEST)
                .body(result);
    }
}
