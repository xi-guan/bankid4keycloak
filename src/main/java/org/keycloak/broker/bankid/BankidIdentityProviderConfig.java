package org.keycloak.broker.bankid;

import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.models.IdentityProviderModel;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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
	
	private KeyStore keyStore;
	private KeyStore truststore;
	
	public BankidIdentityProviderConfig() {
		super();
	}
	
	public BankidIdentityProviderConfig(IdentityProviderModel model) {
		super(model);
	}

	public String getApiUrl() {
		return getConfig().get(BANKID_APIURL_PROPERTY_NAME);
	}
	public KeyStore getKeyStore() throws Exception {
		if ( keyStore == null ) {
			keyStore = KeystoreUtil.loadKeyStore(
				getConfig().get(BANKID_KEYSTORE_FILE_PROPERTY_NAME),
				getConfig().getOrDefault(BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME, "changeit"));
		}
		return keyStore;
	}
	public KeyStore getTrustStore() throws Exception {
    if (truststore == null) {
      var certFactory = CertificateFactory.getInstance("X.509");
      var certPath = getConfig().get(BANKID_TRUSTSTORE_FILE_PROPERTY_NAME);
      var certCA = (X509Certificate) certFactory.generateCertificate(Files.newInputStream(Paths.get(certPath)));
      var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null);
      keyStore.setCertificateEntry("caCert", certCA);
      return keyStore;
    }
    return truststore;
	}
	
	public String getPrivateKeyPassword() {
		return getConfig().getOrDefault(BANKID_PRIVATEKEY_PASSWORD_PROPERTY_NAME, "changeit");
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
