package com.github.h3yow.securityeventpipelinejava.ingest;

import com.github.h3yow.securityeventpipelinejava.model.RejectionReason;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** 日志接入接入 API。 */
@RestController
@RequestMapping("/api/logs")
public class IngestController {

    private final IngestService ingestService;

    public IngestController(IngestService ingestService) {
        this.ingestService = ingestService;
    }

    /**
     * 接入一条原始日志。
     * 接受 → 200；重复（幂等）→ 200 且 reason=DUPLICATE；拒绝 → 422 且携带可区分原因。
     */
    @PostMapping
    public ResponseEntity<IngestResult> ingest(@RequestBody RawLogRequest request) {
        IngestResult result = ingestService.ingest(request);
        if (result.accepted() || result.reason() == RejectionReason.DUPLICATE) {
            return ResponseEntity.ok(result);
        }
        return ResponseEntity.unprocessableEntity().body(result);
    }
}
