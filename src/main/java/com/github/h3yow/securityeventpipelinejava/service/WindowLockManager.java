package com.github.h3yow.securityeventpipelinejava.service;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 窗口级 JVM 锁注册表。
 *
 * <p>所有对同一窗口（{@code ruleId#vN#groupKey#windowStart}）的变更——实时事件累计与
 * 运维发起的自愈——都必须通过这里拿到同一把锁后再进入数据库事务，从而把同窗口的
 * 读-改-写串行化，避免在事务内部撞上 {@code uk_window_event} 唯一约束导致整事务回滚。
 * 不同窗口之间仍完全并行。
 */
@Component
public class WindowLockManager {

    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public Lock lockFor(String windowKey) {
        return locks.computeIfAbsent(windowKey, k -> new ReentrantLock());
    }
}
