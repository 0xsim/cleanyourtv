package io.github.securetv.watchdog;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * TLS for mqtts and syslog+tls. The certificate is always checked, and so is the host name: against
 * the system's CAs, or against ca_pem alone when the owner gives one (a home broker with its own CA).
 * There is deliberately no way to switch the check off.
 */
final class Tls {
    private Tls() {
    }

    static SSLSocketFactory factory(String caPem) throws IOException {
        if (caPem == null) return (SSLSocketFactory) SSLSocketFactory.getDefault();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs =
                    cf.generateCertificates(new ByteArrayInputStream(caPem.getBytes(StandardCharsets.US_ASCII)));
            if (certs.isEmpty()) throw new IOException("ca_pem holds no certificate");
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            int i = 0;
            for (Certificate cert : certs) store.setCertificateEntry("ca" + i++, cert);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(store);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx.getSocketFactory();
        } catch (GeneralSecurityException e) {
            throw new IOException("ca_pem: " + e.getMessage(), e);
        }
    }

    /** Completes the handshake and checks that the certificate names the host we meant to reach. */
    static void handshake(SSLSocket socket, String host) throws IOException {
        socket.startHandshake();
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.getSession())) {
            socket.close();
            throw new SSLPeerUnverifiedException("the certificate does not name " + host);
        }
    }
}
