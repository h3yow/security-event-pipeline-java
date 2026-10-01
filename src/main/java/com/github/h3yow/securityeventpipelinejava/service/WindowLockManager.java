
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
 *
 * <h3>规则版本锁（ruleCode 命名空间）</h3>
 * 同一 ruleCode 的规则升级（创建新版本）与事件接入互斥：事件在锁内读取"受理时刻生效的版本"
 * 并完成窗口更新，升级在锁内写入新版本，二者对该 ruleCode 线性化，
 * 保证"事件只计入受理时生效的版本"在并发交叠下仍确定成立（与对账重算口径一致）。
 * 规则锁键统一加 {@code rule:} 前缀与窗口键区分，全局顺序上规则锁始终先于窗口锁获取。
 */
@Component
public class WindowLockManager {

    /** 规则版本锁键前缀，保证与窗口键（以数字 ruleId 开头）不冲突且排序在前。 */
    private static final String RULE_LOCK_PREFIX = "rule:";

    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    private ReentrantLock lockFor(String key) {
        return locks.computeIfAbsent(key, k -> new ReentrantLock());
    }

    private static String ruleLockKey(String ruleCode) {
        return RULE_LOCK_PREFIX + ruleCode;
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
        runLocked(List.of(), windowKeys, action);
    }

    /**
     * 先按 ruleCode 字典序获取规则版本锁，再按窗口键字典序获取窗口锁后执行动作，
     * 完成后逆序释放。固定顺序（规则锁→窗口锁）避免死锁。供事件接入路径使用：
     * 与同 ruleCode 的规则升级互斥，并与同窗口的其它事件/自愈互斥。
     */
    public void runLocked(Collection<String> ruleCodes, Collection<String> windowKeys,
                          Runnable action) {
        callLocked(ruleCodes, windowKeys, () -> {
            action.run();
            return null;
        });
    }

    /** 同 {@link #runLocked(Collection, Collection, Runnable)}，但动作有返回值。 */
    public <T> T callLocked(Collection<String> ruleCodes, Collection<String> windowKeys,
                            java.util.function.Supplier<T> action) {
        List<String> orderedRules = ruleCodes.stream().distinct().sorted().toList();
        List<String> orderedWindows = windowKeys.stream().distinct().sorted().toList();
        List<ReentrantLock> acquired =
                new ArrayList<>(orderedRules.size() + orderedWindows.size());
        try {
            for (String ruleCode : orderedRules) {
                ReentrantLock lock = lockFor(ruleLockKey(ruleCode));
                lock.lock();
                acquired.add(lock);
            }
            for (String windowKey : orderedWindows) {
                ReentrantLock lock = lockFor(windowKey);
                lock.lock();
                acquired.add(lock);
            }
            return action.get();
        } finally {
            for (int i = acquired.size() - 1; i >= 0; i--) {
                acquired.get(i).unlock();
            }
        }
    }

    /** 在单个 ruleCode 的规则版本锁保护下执行动作（规则升级使用）。 */
    public void runRuleLocked(String ruleCode, Runnable action) {
        runLocked(List.of(ruleCode), List.of(), action);
    }

    /** 规则版本锁保护下执行并返回结果（规则升级使用）。 */
    public <T> T callLocked(String ruleCode, java.util.function.Supplier<T> action) {
        List<ReentrantLock> acquired = new ArrayList<>(1);
        acquired.add(lockFor(ruleLockKey(ruleCode)));
        acquired.get(0).lock();
        try {
            return action.get();
        } finally {
            acquired.get(0).unlock();
        }
    }
}
