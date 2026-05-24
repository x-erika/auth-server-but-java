package com.xerika.auth.common.crypto;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

@ApplicationScoped
public class RsaKeyProvider {

    private static final Logger LOG = Logger.getLogger(RsaKeyProvider.class);
    private static final String ACTIVE_KID_FILE = "active.kid";

    @ConfigProperty(name = "auth.jwt.keys.dir")
    Optional<String> keysDirConfig;

    private final Map<String, KeyPair> keysByKid = new LinkedHashMap<>();
    private String activeKid;

    @PostConstruct
    void init() {
        try {
            Path dir = resolveKeysDir();
            Files.createDirectories(dir);

            loadExistingKeys(dir);

            Path activeKidFile = dir.resolve(ACTIVE_KID_FILE);
            if (Files.exists(activeKidFile)) {
                String stored = Files.readString(activeKidFile).trim();
                if (keysByKid.containsKey(stored)) {
                    activeKid = stored;
                }
            }

            if (activeKid == null) {
                // Either bootstrap fresh, or migrate legacy private.pem/public.pem
                Path legacyPriv = dir.resolve("private.pem");
                Path legacyPub = dir.resolve("public.pem");
                if (Files.exists(legacyPriv) && Files.exists(legacyPub) && keysByKid.isEmpty()) {
                    KeyPair legacy = new KeyPair(loadPublicKey(legacyPub), loadPrivateKey(legacyPriv));
                    String kid = computeKid(legacy.getPublic());
                    keysByKid.put(kid, legacy);
                    writeKeyFiles(dir, kid, legacy);
                    Files.deleteIfExists(legacyPriv);
                    Files.deleteIfExists(legacyPub);
                    LOG.infof("Migrated legacy keypair to kid=%s", kid);
                }

                if (keysByKid.isEmpty()) {
                    KeyPair generated = generateKeyPair();
                    String kid = computeKid(generated.getPublic());
                    writeKeyFiles(dir, kid, generated);
                    keysByKid.put(kid, generated);
                    LOG.infof("Generated initial RSA keypair kid=%s", kid);
                }

                activeKid = keysByKid.keySet().iterator().next();
                Files.writeString(activeKidFile, activeKid, StandardCharsets.US_ASCII);
            }

            LOG.infof("RSA key set: %d total, active=%s", keysByKid.size(), activeKid);
        } catch (Exception e) {
            throw new IllegalStateException("RSA key bootstrap failed", e);
        }
    }

    public PrivateKey privateKey() {
        return keysByKid.get(activeKid).getPrivate();
    }

    public PublicKey publicKey() {
        return keysByKid.get(activeKid).getPublic();
    }

    public String keyId() {
        return activeKid;
    }

    public Map<String, PublicKey> allPublicKeys() {
        Map<String, PublicKey> result = new LinkedHashMap<>();
        for (Map.Entry<String, KeyPair> e : keysByKid.entrySet()) {
            result.put(e.getKey(), e.getValue().getPublic());
        }
        return result;
    }

    public Optional<PublicKey> publicKeyByKid(String kid) {
        KeyPair pair = kid == null ? null : keysByKid.get(kid);
        return Optional.ofNullable(pair).map(KeyPair::getPublic);
    }

    public synchronized String rotate() {
        try {
            Path dir = resolveKeysDir();
            KeyPair generated = generateKeyPair();
            String kid = computeKid(generated.getPublic());
            writeKeyFiles(dir, kid, generated);
            keysByKid.put(kid, generated);
            activeKid = kid;
            Files.writeString(dir.resolve(ACTIVE_KID_FILE), kid, StandardCharsets.US_ASCII);
            LOG.infof("Rotated active signing key to kid=%s", kid);
            return kid;
        } catch (Exception e) {
            throw new IllegalStateException("Key rotation failed", e);
        }
    }

    /**
     * Permanently retire a non-active key. The kid is removed from the in-memory
     * set, the JWKS endpoint stops advertising it, and the PEM files are deleted.
     * Any JWT still signed by the retired key fails validation immediately.
     * Active key cannot be retired (rotate first).
     */
    public synchronized boolean retire(String kid) {
        if (kid == null || kid.isBlank()) {
            return false;
        }
        if (kid.equals(activeKid)) {
            throw new IllegalArgumentException("Cannot retire the active key — rotate first");
        }
        if (!keysByKid.containsKey(kid)) {
            return false;
        }
        keysByKid.remove(kid);
        try {
            Path dir = resolveKeysDir();
            Files.deleteIfExists(dir.resolve(kid + ".private.pem"));
            Files.deleteIfExists(dir.resolve(kid + ".public.pem"));
            LOG.infof("Retired signing key kid=%s", kid);
            return true;
        } catch (Exception e) {
            throw new IllegalStateException("Key retire failed for kid=" + kid, e);
        }
    }

    private void loadExistingKeys(Path dir) throws IOException, GeneralSecurityException {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> stream = Files.list(dir)) {
            for (Path p : (Iterable<Path>) stream::iterator) {
                String name = p.getFileName().toString();
                if (!name.endsWith(".private.pem")) {
                    continue;
                }
                String kid = name.substring(0, name.length() - ".private.pem".length());
                Path pub = dir.resolve(kid + ".public.pem");
                if (!Files.exists(pub)) {
                    continue;
                }
                PrivateKey priv = loadPrivateKey(p);
                PublicKey pubKey = loadPublicKey(pub);
                keysByKid.put(kid, new KeyPair(pubKey, priv));
            }
        }
    }

    private void writeKeyFiles(Path dir, String kid, KeyPair pair) throws IOException {
        writePem(dir.resolve(kid + ".private.pem"), "PRIVATE KEY", pair.getPrivate().getEncoded());
        writePem(dir.resolve(kid + ".public.pem"), "PUBLIC KEY", pair.getPublic().getEncoded());
    }

    private Path resolveKeysDir() {
        if (keysDirConfig.isPresent() && !keysDirConfig.get().isBlank()) {
            return Paths.get(keysDirConfig.get());
        }
        return Paths.get(System.getProperty("user.home"), ".xerika", "auth", "keys");
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private PrivateKey loadPrivateKey(Path path) throws IOException, GeneralSecurityException {
        byte[] bytes = parsePem(Files.readString(path), "PRIVATE KEY");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    private PublicKey loadPublicKey(Path path) throws IOException, GeneralSecurityException {
        byte[] bytes = parsePem(Files.readString(path), "PUBLIC KEY");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    }

    private byte[] parsePem(String pem, String type) {
        String header = "-----BEGIN " + type + "-----";
        String footer = "-----END " + type + "-----";
        String stripped = pem.replace(header, "").replace(footer, "").replaceAll("\\s+", "");
        return Base64.getDecoder().decode(stripped);
    }

    private void writePem(Path path, String type, byte[] encoded) throws IOException {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
            .encodeToString(encoded);
        String pem = "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
        // Write tmp + ATOMIC_MOVE so a crash mid-write can't leave a half-written
        // .pem on disk — private keys are the worst-case (corrupt file blocks startup).
        Path tmp = path.resolveSibling(path.getFileName().toString() + ".tmp");
        Files.writeString(tmp, pem, StandardCharsets.US_ASCII);
        Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        // Private key files: tighten to owner-only on POSIX. Windows NTFS uses ACLs
        // that need a different API — accept the umask default there (learning project).
        if ("PRIVATE KEY".equals(type)) {
            try {
                Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
                ));
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX filesystem (Windows).
            }
        }
    }

    private String computeKid(PublicKey key) throws NoSuchAlgorithmException {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash).substring(0, 16);
    }
}
