package com.github.h3yow.securityeventpipelinejava.service;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

/**
 * 规则部署与事件受理之间的版本边界协调器（JVM 内）。
 *
 * <h3>为什么需要它</h3>
 * 事件按<b>受理时刻</b>归属到当时生效的规则版本。规则升级与同窗口的并发补录/重放交叠时，
 * 必须保证"一次受理读规则集 → 落库"的全过程看到的是同一个部署版本，否则实时链路使用的版本
 * 与事后按受理时间重算的归属可能互相矛盾。这里用一把公平读写锁定义两种临界区：
 * <ul>
 *   <li><b>读视图（readView）</b>：事件受理（检测/窗口计数/对账/自愈重算）持有，彼此并行；</li>
 *   <li><b>升级（upgrade）</b>：规则发布新版本独占持有，与所有受理互斥。</li>
 * </ul>
 *
 * <h3>边界时间戳的单调性</h3>
 * 数据库时间戳精度可能低于 {@link Instant}（H2 默认微秒），同一微秒内"先受理后升级"
 * 落库后可能被截断成相等时刻。因此：
 * <ul>
 *   <li>读视图内通过 {@link #acceptedAt()} 取受理时刻，并记录读视图已使用的最大时刻；</li>
 *   <li>升级时通过 {@link #nextVersionCreatedAt()} 取新版本生效时刻，且强制严格大于
 *       任何已完成读视图的受理时刻与上一版本生效时刻（至少晚 1 微秒）。</li>
 * </ul>
 * 于是版本生效区间 [createdAt_v, createdAt_{v+1}) 与读锁看到的规则集严格对应：
 * 区间内受理的事件一定只可能命中 v；恰好落在边界的事件归属也唯一、可解释。
 */
@Component
public class RuleDeploymentLock {

    /** 读视图已使用的最大受理时刻（多线程读视图并发更新）。 */
    private final AtomicReference<Instant> lastAcceptedAt = new AtomicReference<>(Instant.EPOCH);
    /** 上一版本生效时刻（仅在升级写锁内访问）。 */
    private Instant lastCreatedAt = Instant.EPOCH;

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    /** 在稳定的规则部署读视图内执行并返回结果。 */
    public <T> T readView(Supplier<T> action) {
        lock.readLock().lock();
        try {
            return action.get();
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 独占执行一次规则版本发布；提交（事务）在锁内完成后才放行新的受理。 */
    public <T> T upgrade(Supplier<T> action) {
        lock.writeLock().lock();
        try {
            return action.get();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 读视图内调用：返回本次受理使用的受理时刻（墙上时钟），并推进读视图时间水位。
     * 不主动顺延——读视图看到的版本由锁保证，边界另一侧的顺延由升级侧负责。
     */
    public Instant acceptedAt() {
        Instant now = Instant.now();
        lastAcceptedAt.updateAndGet(prev -> now.isAfter(prev) ? now : prev);
        return now;
    }

    /**
     * 升级写锁内调用：返回新版本的生效时刻。该时刻严格晚于任何已完成读视图的受理时刻
     * 与上一版本生效时刻（至少 +1 微秒），消除时间戳存储截断导致的边界二义性。
     */
    public Instant nextVersionCreatedAt() {
        Instant floor = lastAcceptedAt.get().plusNanos(1_000);
        Instant t = Instant.now();
        if (!t.isAfter(floor)) {
            t = floor;
        }
        if (!t.isAfter(lastCreatedAt)) {
            t = lastCreatedAt.plusNanos(1_000);
        }
        lastCreatedAt = t;
        return t;
    }
}
