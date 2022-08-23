package org.keycloak.broker.bankid;

import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.models.IdentityProviderModel;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.concurrent.atomic.AtomicReference;

public class BankidIdentityProviderConfig extends IdentityProviderModel {
  private static final long serialVersionUID = 3849007589404817838L;
	
	private static final String BANKID_APIURL_PROPERTY_NAME = "bankid_apiurl";
	private static final String BANKID_KEYSTORE_FILE_PROPERTY_NAME = "bankid_keystore_file";
	private static final String BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME = "bankid_keystore_password";
	private static final String BANKID_TRUSTSTORE_FILE_PROPERTY_NAME = "bankid_truststore_file";
	private static final String BANKID_TRUSTSTORE_PASSWORD_PROPERTY_NAME = "bankid_truststore_password";
	private static final String BANKID_PRIVATEKEY_PASSWORD_PROPERTY_NAME = "bankid_privatekey_password";
	private static final String BANKID_REQUIRE_NIN = "bankid_require_nin";
	private static final String BANKID_SHOW_QR_CODE = "bankid_show_qr_code";
	private static final String BANKID_SAVE_NIN_HASH = "bankid_save_nin_hash";
  private static final String DEFAULT_PASSWORD = "changeit";
  
  private final AtomicReference<KeyStore> keyStoreRef = new AtomicReference<>();
	private final AtomicReference<KeyStore> truststoreRef = new AtomicReference<>();
  
  public BankidIdentityProviderConfig() {super();}
  
  public BankidIdentityProviderConfig(IdentityProviderModel model) {super(model);}
  
  public String getApiUrl() {return getConfig().get(BANKID_APIURL_PROPERTY_NAME);}
  
  public KeyStore getKeyStore() throws Exception {
    var keystore = keyStoreRef.get();
    if (keystore == null) {
      keystore = KeystoreUtil.loadKeyStore(getKeystoreFilePath(), getKeyStorePassword());
      if (!keyStoreRef.compareAndSet(null, keystore)) {
        return keyStoreRef.get();
      }
    }
    return keystore;
  }
  
  public KeyStore getTrustStore() throws Exception {
    var truststore = truststoreRef.get();
    if (truststore == null) {
      var certFactory = CertificateFactory.getInstance("X.509");
      var certPath = getTruststoreFilePath();
      var certCA = certFactory.generateCertificate(Files.newInputStream(Paths.get(certPath)));
      truststore = KeyStore.getInstance(KeyStore.getDefaultType());
      truststore.load(null);
      truststore.setCertificateEntry("caCert", certCA);
      if (!truststoreRef.compareAndSet(null, truststore)) {
        return truststoreRef.get();
      }
    }
    return truststore;
  }
  
  private String getKeyStorePassword() {return getConfig().getOrDefault(BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME, DEFAULT_PASSWORD);}
  
  private String getKeystoreFilePath() {return getConfig().get(BANKID_KEYSTORE_FILE_PROPERTY_NAME);}
  
  private String getTruststoreFilePath() {
    return getConfig().get(BANKID_TRUSTSTORE_FILE_PROPERTY_NAME);
  }
  
  public String getPrivateKeyPassword() {
		return getConfig().getOrDefault(BANKID_PRIVATEKEY_PASSWORD_PROPERTY_NAME, DEFAULT_PASSWORD);
	}
	
	public boolean isShowQRCode() {
		return Boolean.parseBoolean(getConfig().getOrDefault(BANKID_SHOW_QR_CODE, "false"));
	}
	
	public boolean isRequiredNin() {
		return Boolean.parseBoolean(getConfig().getOrDefault(BANKID_REQUIRE_NIN, "false"));
	}
	
	public boolean isSaveNinHashed() {
		return Boolean.parseBoolean(getConfig().getOrDefault(BANKID_SAVE_NIN_HASH, "false"));
	}
}
