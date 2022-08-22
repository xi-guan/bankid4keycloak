package org.keycloak.broker.bankid;

import org.apache.http.client.HttpClient;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.connections.httpclient.HttpClientBuilder;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;

public class BankidIdentityProvider extends AbstractIdentityProvider<BankidIdentityProviderConfig> {
  
  public BankidIdentityProvider(KeycloakSession session, BankidIdentityProviderConfig config) {
    super(session, config);
  }
  
  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new BankidEndpoint(this, getConfig(), callback);
  }
  
  @Override
  public Response performLogin(AuthenticationRequest request) {
    try {
      return Response.status(302).location(new URI(request.getRedirectUri() + "/start?state=" + request.getState().getEncoded())).build();
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException();
    }
  }
  
  public KeycloakSession getSession() {
    return this.session;
  }
  
  @Override
  public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
    return Response.ok(identity.getToken()).build();
  }
  
  public HttpClient buildBankidHttpClient() {
    try {
      KeyStore keystore = getConfig().getKeyStore();
      String keystorePassword = getConfig().getPrivateKeyPassword();
      KeyStore truststore = getConfig().getTrustStore();
      return buildBankidHttpClient(keystore, keystorePassword, truststore);
    } catch (Exception e) {
      throw new RuntimeException("Failed to create BankID HTTP Client", e);
    }
  }
  
  public HttpClient buildBankidHttpClient(KeyStore keystore, String keystorePassword, KeyStore trustStore) {
    try {
      return (new HttpClientBuilder()).keyStore(keystore, keystorePassword).trustStore(trustStore).build();
    } catch (Exception e) {
      throw new RuntimeException("Failed to create BankID HTTP Client", e);
    }
  }
  
}
