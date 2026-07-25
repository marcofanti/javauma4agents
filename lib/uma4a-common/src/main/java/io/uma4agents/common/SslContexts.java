package io.uma4agents.common;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Builds an {@link SSLContext} trusting the lab CA bundle (rootCA.pem) without
 * touching the JVM default truststore. Every outbound TLS call in the lab —
 * to Keycloak, the person-server, or through the Envoy edge — goes through this.
 */
public final class SslContexts {

    private SslContexts() {}

    public static SSLContext fromPem(Path caBundle) {
        try (InputStream in = Files.newInputStream(caBundle)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(in);
            if (certs.isEmpty()) {
                throw new IllegalArgumentException("no certificates in " + caBundle);
            }
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int i = 0;
            for (Certificate cert : certs) {
                ks.setCertificateEntry("ca-" + i++, cert);
            }
            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot build SSLContext from " + caBundle, e);
        }
    }
}
