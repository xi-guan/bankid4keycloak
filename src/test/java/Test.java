import org.apache.http.client.HttpClient;
import org.keycloak.broker.bankid.client.SimpleBankidClient;
import org.keycloak.broker.bankid.model.AuthResponse;
import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.connections.httpclient.HttpClientBuilder;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Test {
  public static void main(String[] args) throws Exception {
    var keyStore = getKeyStore();
    var trustStore = getTrustStore();
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
      return builder.keyStore(keystore, keystorePassword)
        .trustStore(trustStore)
        .build();
    } catch (Exception e) {
      throw new RuntimeException("Failed to create BankID HTTP Client", e);
    }
  }
  
  public static KeyStore getKeyStore() throws Exception {
    String filename = "/Users/xig/Dev/0Projects/forebygga/keycloak/certs/keystore.p12";
    String password = "qwerty123";
    return KeystoreUtil.loadKeyStore(filename, password);
  }
  
  public static KeyStore getTrustStore() throws Exception {
    var certificateFactory = CertificateFactory.getInstance("X.509");
    var certPath = "/Users/xig/Dev/0Projects/forebygga/keycloak/certs/bankid-ca.test.crt";
    var caCert = (X509Certificate) certificateFactory.generateCertificate(Files.newInputStream(Paths.get(certPath)));
    
    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null);
    keyStore.setCertificateEntry("abc123", caCert);
    return keyStore;
  }
}
