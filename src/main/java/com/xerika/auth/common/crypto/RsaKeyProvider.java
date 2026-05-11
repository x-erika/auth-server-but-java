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
import java.util.Optional;

@ApplicationScoped
public class RsaKeyProvider {

    private static final Logger LOG = Logger.getLogger(RsaKeyProvider.class);

    @ConfigProperty(name = "auth.jwt.keys.dir")
    Optional<String> keysDirConfig;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String keyId;

    @PostConstruct
    void init() {
        try {
            Path dir = resolveKeysDir();
            Path privatePath = dir.resolve("private.pem");
            Path publicPath = dir.resolve("public.pem");

            if (Files.exists(privatePath) && Files.exists(publicPath)) {
                this.privateKey = loadPrivateKey(privatePath);
                this.publicKey = loadPublicKey(publicPath);
                LOG.infof("Loaded RSA keypair from %s", dir);
            } else {
                KeyPair keyPair = generateKeyPair();
                this.privateKey = keyPair.getPrivate();
                this.publicKey = keyPair.getPublic();
                Files.createDirectories(dir);
                writePem(privatePath, "PRIVATE KEY", privateKey.getEncoded());
                writePem(publicPath, "PUBLIC KEY", publicKey.getEncoded());
                LOG.infof("Generated RSA keypair at %s", dir);
            }

            this.keyId = computeKid(publicKey);
        } catch (Exception e) {
            throw new IllegalStateException("RSA key bootstrap failed", e);
        }
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    public String keyId() {
        return keyId;
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
        Files.writeString(path, pem, StandardCharsets.US_ASCII);
    }

    private String computeKid(PublicKey key) throws NoSuchAlgorithmException {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash).substring(0, 16);
    }
}
