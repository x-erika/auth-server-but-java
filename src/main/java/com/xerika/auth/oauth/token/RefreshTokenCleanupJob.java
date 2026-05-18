package com.xerika.auth.oauth.token;

import io.quarkus.scheduler.Scheduled;
import io.quarkus.scheduler.Scheduled.ConcurrentExecution;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.jboss.logging.Logger;

import java.time.LocalDateTime;

/**
 * Periodic sweep of refresh_tokens that are expired or revoked.
 *
 * <p>FK CASCADE on session_id already removes refresh tokens when their session
 * is deleted, so most rows disappear via logout. But rotated/revoked tokens
 * persist as long as their session lives (8h) — and a user that refreshes often
 * without logging out accumulates one revoked row per refresh. This job caps
 * that growth.
 */
@ApplicationScoped
public class RefreshTokenCleanupJob {

    private static final Logger LOG = Logger.getLogger(RefreshTokenCleanupJob.class);

    @PersistenceContext
    EntityManager em;

    // Runs hourly; SKIP overlap so a slow query on a large table can't pile up
    // concurrent deletes. Identity = "refresh-cleanup" so the metric is visible.
    @Scheduled(every = "1h", concurrentExecution = ConcurrentExecution.SKIP, identity = "refresh-cleanup")
    @Transactional
    public void cleanup() {
        int deleted = em.createQuery(
                "DELETE FROM RefreshToken r WHERE r.revoked = true "
                    + "OR (r.expiresAt IS NOT NULL AND r.expiresAt < :now)"
            )
            .setParameter("now", LocalDateTime.now())
            .executeUpdate();
        if (deleted > 0) {
            LOG.infof("Refresh token sweep: removed %d expired/revoked rows", deleted);
        }
    }
}
