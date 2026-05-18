package com.xerika.auth.bootstrap;

import jakarta.persistence.EntityManager;

/**
 * Postgres advisory lock used to serialise startup-time bootstrap inserts when
 * multiple replicas race. {@code pg_advisory_xact_lock} blocks until the lock
 * is granted, then auto-releases at transaction commit/rollback — so every
 * bootstrap that uses it must run inside {@code @Transactional}.
 *
 * <p>Single key shared across all bootstraps: the cost of serialising them is
 * negligible (each runs once per process) and avoids the complexity of picking
 * non-overlapping keys per concern.
 */
final class BootstrapLock {

    // Arbitrary stable long. Chosen to be unlikely to collide with anything else
    // the app might use pg_advisory_lock for in the future.
    private static final long LOCK_KEY = 0x5845524B4142434FL; // "XERKABCO"

    private BootstrapLock() {
    }

    static void acquire(EntityManager em) {
        em.createNativeQuery("SELECT pg_advisory_xact_lock(?1)")
            .setParameter(1, LOCK_KEY)
            .getSingleResult();
    }
}
