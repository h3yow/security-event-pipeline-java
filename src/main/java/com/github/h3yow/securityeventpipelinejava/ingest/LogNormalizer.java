package com.github.h3yow.securityeventpipelinejava.ingest;

import com.github.h3yow.securityeventpipelinejava.model.EventSource;
import com.github.h3yow.securityeventpipelinejava.model.NormalizedEvent;

/** 原始报文 → 归一化事件 的解析器。 */
public interface LogNormalizer {

    /** 该解析器处理的来源类型。 */
    EventSource supportedSource();

    /**
     * 解析原始报文。
     *
     * @param eventId 幂等键
     * @param payload 原始报文
     * @return 归一化事件（receivedAt/groupKey 由调用方补充）
     * @throws NormalizationException 解析失败，携带可区分原因
     */
    NormalizedEvent normalize(String eventId, String payload) throws NormalizationException;
}
