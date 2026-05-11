package com.xerika.auth.oauth.device;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@ApplicationScoped
public class DeviceAuthorizationRepository {

    @PersistenceContext
    EntityManager em;

    public Optional<DeviceAuthorization> findByDeviceCode(String deviceCode) {
        return em.createQuery(
                "SELECT d FROM DeviceAuthorization d WHERE d.deviceCode = :code",
                DeviceAuthorization.class
            )
            .setParameter("code", deviceCode)
            .getResultStream()
            .findFirst();
    }

    public Optional<DeviceAuthorization> findByUserCode(String userCode) {
        return em.createQuery(
                "SELECT d FROM DeviceAuthorization d WHERE d.userCode = :code",
                DeviceAuthorization.class
            )
            .setParameter("code", userCode)
            .getResultStream()
            .findFirst();
    }

    @Transactional
    public void persist(DeviceAuthorization auth) {
        em.persist(auth);
    }

    @Transactional
    public DeviceAuthorization update(DeviceAuthorization auth) {
        return em.merge(auth);
    }

    @Transactional
    public int deleteExpired() {
        return em.createQuery(
                "DELETE FROM DeviceAuthorization d WHERE d.expiresAt < :now"
            )
            .setParameter("now", LocalDateTime.now())
            .executeUpdate();
    }
}
