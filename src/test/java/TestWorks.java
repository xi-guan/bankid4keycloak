import org.apache.http.client.HttpClient;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.keycloak.broker.bankid.BankidIdentityProviderConfig;
import org.keycloak.broker.bankid.client.SimpleBankidClient;
import org.keycloak.broker.bankid.model.AuthResponse;
import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.connections.httpclient.HttpClientBuilder;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class TestWorks {
  public static void main(String[] args) throws Exception {
    BankidIdentityProviderConfig bankidIdentityProviderConfig = new BankidIdentityProviderConfig();
    KeyStore keyStore = getKeyStore();
    KeyStore trustStore = getTrustStore();
    String password = "qwerty123";
    HttpClient httpclient = buildBankidHttpClient(keyStore, password, trustStore);
    SimpleBankidClient bankidClient = new SimpleBankidClient(httpclient, "https://appapi2.test.bankid.com");
    AuthResponse authResponse = bankidClient.sendAuth("199712152397", "178.222.224.50");
    System.out.printf("Auth response: [%s, %s]%n", authResponse.getOrderRef(),
      authResponse.getAutoStartToken());
  }
  
  public static HttpClient buildBankidHttpClient(KeyStore keystore, String keystorePassword, KeyStore trustStore) {
    try {
      HttpClientBuilder builder = new HttpClientBuilder();
      File test = new File("/Users/xig/Downloads/Github/bankid-java-sdk/src/main/resources/test.p12");
      String password = "qwerty123";
      File ca = new File("/Users/xig/Downloads/Github/bankid-java-sdk/src/main/resources/ca.test.crt");
      KeyManagerFactory keyManagerFactory = tryCreateKeyManager(test.toPath(), password);
      TrustManagerFactory trustManagerFactory = tryCreateTrustManager(ca.toPath());
      return builder.sslContext(tryCreateSSLContext(keyManagerFactory, trustManagerFactory)).build();
    } catch (Exception e) {
      throw new RuntimeException("Failed to create BankID HTTP Client", e);
    }
  }
  
  public static KeyStore getKeyStore() throws Exception {
    String filename = "/Users/xig/Dev/0Projects/forebygga/keycloak/keycloak_conf/keystores/keystore.p12";
    String password = "qwerty123";
    return KeystoreUtil.loadKeyStore(filename, password);
  }
  
  public static KeyStore getTrustStore() throws Exception {
    String filename = "/Users/xig/Downloads/Github/bankid-java-sdk/src/main/resources/ca.test.crt";
    String password = "qwerty123";
    return KeystoreUtil.loadKeyStore(filename, password);
  }
  
  public static SSLContext tryCreateSSLContext(
    final KeyManagerFactory keyManagerFactory,
    final TrustManagerFactory trustManagerFactory
  ) throws NoSuchAlgorithmException, KeyManagementException {
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
    sslContext.init(keyManagers, trustManagers, new SecureRandom());
    return sslContext;
  }
  
  public static KeyManagerFactory tryCreateKeyManager(@NonNull final Path path, @NonNull final String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
    final KeyStore clientStore = KeyStore.getInstance("PKCS12");
    
    try (final InputStream inputStream = Files.newInputStream(path)) {
      clientStore.load(inputStream, password.toCharArray());
    }
    
    final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(clientStore, password.toCharArray());
    
    return keyManagerFactory;
  }
  
  public static TrustManagerFactory tryCreateTrustManager(@NonNull final Path path) throws CertificateException,
    IOException, NoSuchAlgorithmException, KeyStoreException {
    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    final X509Certificate caCert = (X509Certificate) certificateFactory.generateCertificate(Files.newInputStream(path));
    
    final TrustManagerFactory trustManagerFactory = TrustManagerFactory
      .getInstance(TrustManagerFactory.getDefaultAlgorithm());
    
    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null);
    keyStore.setCertificateEntry("caCert", caCert);
    
    trustManagerFactory.init(keyStore);
    
    return trustManagerFactory;
  }
}
