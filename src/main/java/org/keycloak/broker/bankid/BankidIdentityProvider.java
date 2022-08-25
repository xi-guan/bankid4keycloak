package org.keycloak.broker.bankid;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import org.apache.http.client.HttpClient;
import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.broker.bankid.client.BankidClient;
import org.keycloak.broker.bankid.client.BankidClientException;
import org.keycloak.broker.bankid.model.AuthResponse;
import org.keycloak.broker.bankid.model.BankidHintCodes;
import org.keycloak.broker.bankid.model.BankidUser;
import org.keycloak.broker.bankid.model.CollectResponse;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.connections.httpclient.HttpClientBuilder;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class BankidIdentityProvider extends AbstractIdentityProvider<BankidIdentityProviderConfig> {
  private static final Map<String, AuthResponse> authRespMap = new ConcurrentHashMap<>();
  private static final Map<String, BankidUser> userMap = new ConcurrentHashMap<>();
  private static final String STATE = "state";
  public static final String START_BANKID_TEMPLATE = "start-bankid.ftl";
  
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
      var keystore = getConfig().getKeyStore();
      var privateKeyPassword = getConfig().getPrivateKeyPassword();
      var truststore = getConfig().getTrustStore();
      return buildBankidHttpClient(keystore, privateKeyPassword, truststore);
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
  
  protected static class BankidEndpoint {
    public static final String ERROR = "bankid.hints.";
    private final Logger logger = Logger.getLogger(BankidEndpoint.class);
    private final BankidIdentityProviderConfig config;
    private final AuthenticationCallback callback;
    private final BankidIdentityProvider provider;
    private final BankidClient bankidClient;
    
    @Context
    protected KeycloakSession session;
    
    @Context
    protected ClientConnection clientConnection;
    
    @Context HttpRequest request;
    
    @Context
    protected HttpHeaders headers;
    
    public BankidEndpoint(BankidIdentityProvider provider, BankidIdentityProviderConfig config,
      AuthenticationCallback callback) {
      this.config = config;
      this.callback = callback;
      this.provider = provider;
      this.bankidClient = new BankidClient(provider.buildBankidHttpClient(), config.getApiUrl());
    }
    
    @GET
    @Path("/start")
    public Response start(@QueryParam(STATE) String state) {
      if (state == null) {
        logger.error("/start -> state is null");
        return callback.error(ERROR + BankidHintCodes.internal.messageShortName);
      }
      if (config.isRequiredNin()) {
        var loginForm = provider.getSession().getProvider(LoginFormsProvider.class);
        return loginForm.setAttribute(STATE, state).createForm(START_BANKID_TEMPLATE);
      } else {
        // Go direct to login if we do not require non.
        return doLogin(null, state);
      }
    }
    
    @POST
    @Path("/login")
    public Response loginPost(@FormParam("nin") String nin, @FormParam(STATE) String state) {
      return doLogin(nin, state);
    }
    
    @GET
    @Path("/login")
    public Response loginGet(@Context HttpRequest request) {
      logger.info("get /login is called, so no state will be get");
      return doLogin(null, null);
    }
    
    private Response doLogin(String nin, String state) {
      var loginForm = provider.getSession().getProvider(LoginFormsProvider.class);
      if (state == null) {
        logger.info("doLogin, state is null, so will send error back");
        clearAllBankidFromSession(null);
        return loginForm.setError(ERROR + BankidHintCodes.internal.messageShortName)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      }
      try {
        var authResponse = getSessionAuthResp(state);
        if (authResponse == null) {
          logger.info("doLogin, state is not null, but failed to get related auth response, so send it");
          logger.info("ip address: " + clientConnection.getRemoteAddr());
          authResponse = bankidClient.sendAuth(nin, "81.232.1.186");
          logger.info("get auth response: " + authResponse);
          setSessionAuthResp(state, authResponse);
        }
        
        return loginForm.setAttribute(STATE, state)
          .setAttribute("autoStartToken", authResponse.getAutoStartToken())
          .setAttribute("showqr", config.isShowQRCode()).setAttribute("ninRequired", config.isRequiredNin())
          .createForm("login-bankid.ftl");
      } catch (BankidClientException e) {
        logger.error("error when perform do login", e);
        clearAllBankidFromSession(state);
        return loginForm.setError(ERROR + e.getHintCode().messageShortName)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      }
    }
    
    @GET
    @Path("/collect")
    public Response collect(@Context HttpRequest request, @QueryParam(STATE) String state) {
      var authResp = getSessionAuthResp(state);
      if (authResp != null) {
        String orderRef = authResp.getOrderRef();
        try {
          CollectResponse responseData = bankidClient.sendCollect(orderRef);
          // Check responseData.getStatus()
          if ("failed".equalsIgnoreCase(responseData.getStatus())) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
              .entity(String.format("{ \"status\": \"%s\", \"hintCode\": \"%s\" }",
                responseData.getStatus(), responseData.getHintCode()))
              .type(MediaType.APPLICATION_JSON_TYPE).build();
          } else {
            if ("complete".equalsIgnoreCase(responseData.getStatus())) {
              removeAuthResp(state);
              setSessionUser(state, responseData.getCompletionData().getUser());
            }
            return Response.ok(String.format("{ \"status\": \"%s\", \"hintCode\": \"%s\" }",
                responseData.getStatus(), responseData.getHintCode()), MediaType.APPLICATION_JSON_TYPE)
              .build();
          }
        } catch (BankidClientException e) {
          return Response
            .status(Response.Status.INTERNAL_SERVER_ERROR).entity(String
              .format("{ \"status\": \"%s\", \"hintCode\": \"%s\" }", "failed", e.getHintCode()))
            .type(MediaType.APPLICATION_JSON_TYPE).build();
        }
      } else {
        return Response.ok(String.format("{ \"status\": \"%s\", \"hintCode\": \"%s\" }", "500", "internal"),
          MediaType.APPLICATION_JSON_TYPE).build();
      }
    }
    
    @GET
    @Path("/done")
    public Response done(@Context HttpRequest request, @QueryParam(STATE) String state) {
      if (state == null) {
        clearAllBankidFromSession(null);
        return callback.error(ERROR + BankidHintCodes.internal.messageShortName);
      }
      
      LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);
      
      var user = getSessionUser(state);
      if (user == null) {
        logger.error("Session attribute 'bankidUser' not set or not correct type.");
        clearAllBankidFromSession(state);
        return loginFormsProvider.setError("bankid.error.internal").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      }
      clearAllBankidFromSession(state);
      try {
        var authSession = this.callback.getAndVerifyAuthenticationSession(state);
        session.getContext().setAuthenticationSession(authSession);
        BrokeredIdentityContext identity = new BrokeredIdentityContext(getUsername(user));
        identity.setIdpConfig(config);
        identity.setIdp(provider);
        identity.setUsername(getUsername(user));
        identity.setFirstName(user.getGivenName());
        identity.setLastName(user.getSurname());
        identity.setAuthenticationSession(authSession);
        return callback.authenticated(identity);
      } catch (Exception e) {
        throw new RuntimeException("Failed to decode user information.", e);
      }
    }
    
    private String getUsername(BankidUser user) throws NoSuchAlgorithmException {
      if (this.config.isSaveNinHashed()) {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(user.getPersonalNumber().getBytes());
        return Base64.getEncoder().encodeToString(md.digest());
      } else {
        return user.getPersonalNumber();
      }
    }
    
    @GET
    @Path("/cancel")
    public Response cancel(@QueryParam(STATE) String state) {
      if (state == null) {
        return callback.error(ERROR + BankidHintCodes.internal.messageShortName);
      }
      AuthResponse authResponse = getSessionAuthResp(state);
      if (authResponse != null) {
        String orderRef = authResponse.getOrderRef();
        bankidClient.sendCancel(orderRef);
      }
      boolean noAuthSession = session.getContext().getAuthenticationSession() == null;
      if (noAuthSession) {
        session.getContext().setAuthenticationSession(callback.getAndVerifyAuthenticationSession(state));
      }
      return callback.error(ERROR + BankidHintCodes.cancelled.messageShortName);
    }
    
    @GET
    @Path("/error")
    public Response error(@QueryParam("code") String hintCode, @QueryParam(STATE) String state) {
      // Make sure to remove the authresponse attribute from the session
      clearAllBankidFromSession(state);
      
      BankidHintCodes hint;
      // Sanitize input from the web
      try {
        hint = BankidHintCodes.valueOf(hintCode);
      } catch (IllegalArgumentException e) {
        hint = BankidHintCodes.unkown;
      }
      LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);
      return loginFormsProvider.setError(ERROR + hint.messageShortName)
        .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
    }
    
    @GET
    @Path("/qrcode")
    public Response qrcode(@Context HttpRequest request, @QueryParam(STATE) String state) {
      AuthResponse authResponse = getSessionAuthResp(state);
      if (authResponse != null) {
        try {
          int width = 246;
          int height = 246;
          QRCodeWriter writer = new QRCodeWriter();
          final var bitMatrix = writer.encode("bankid:///?autostarttoken=" + authResponse.getAutoStartToken(), BarcodeFormat.QR_CODE, width, height);
          ByteArrayOutputStream bos = new ByteArrayOutputStream();
          MatrixToImageWriter.writeToStream(bitMatrix, "png", bos);
          bos.close();
          return Response.ok(bos.toByteArray(), "image/png").build();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
      return Response.serverError().build();
    }
  
    private AuthResponse getSessionAuthResp(String state) {
      return authRespMap.get(state);
    }
  
    private void setSessionAuthResp(String state, AuthResponse authResp) {
      authRespMap.put(state, authResp);
    }
    
    private void removeAuthResp(String state) {
      authRespMap.remove(state);
    }
    
    private void setSessionUser(String state, BankidUser user) {
      userMap.put(state, user);
    }
    
    private BankidUser getSessionUser(String state) {
      return userMap.get(state);
    }
  
    private void clearAllBankidFromSession(String state) {
      authRespMap.remove(state);
      userMap.remove(state);
    }
    
  }
  
}
