
package com.github.h3yow.securityeventpipelinejava.service;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * JVM 内按窗口键（WindowKey.encode()）互斥的锁管理器。
 *
 * <p>检测接入路径与窗口自愈路径共用同一把锁，且<b>锁的持有必须覆盖整个数据库事务</b>：
 * 否则"读聚合→插入关联行→改计数→提交"之间锁被释放，并发的不同事件会产生
 * 聚合行唯一约束冲突（新窗口）或计数丢失更新（已有窗口）。
 *
 * <p>一个事件可能同时命中多个规则（对应多个窗口键），因此支持一次按字典序获取多把锁，
 * 固定加锁顺序以避免死锁。
 */
@Component
public class WindowLockManager {

    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    private ReentrantLock lockFor(String windowKey) {
        return locks.computeIfAbsent(windowKey, k -> new ReentrantLock());
    }

    /** 在单个窗口锁的保护下执行动作；锁覆盖动作全过程（调用方应让事务在动作内提交）。 */
    public void runLocked(String windowKey, Runnable action) {
        ReentrantLock lock = lockFor(windowKey);
        lock.lock();
        try {
            action.run();
        } finally {
            lock.unlock();
        }
    }

    /** 按窗口键字典序依次加锁后执行动作，完成后逆序释放；重复键只取一次。 */
    public void runLocked(Collection<String> windowKeys, Runnable action) {
        List<String> ordered = windowKeys.stream().distinct().sorted().toList();
        List<ReentrantLock> acquired = new ArrayList<>(ordered.size());
        try {
            for (String key : ordered) {
                ReentrantLock lock = lockFor(key);
                lock.lock();
                acquired.add(lock);
            }
            action.run();
        } finally {
            for (int i = acquired.size() - 1; i >= 0; i--) {
                acquired.get(i).unlock();
            }
        }
    }
}
