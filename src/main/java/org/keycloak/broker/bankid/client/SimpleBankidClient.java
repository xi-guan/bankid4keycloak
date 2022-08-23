package org.keycloak.broker.bankid.client;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.client.HttpClient;
import org.jboss.logging.Logger;
import org.keycloak.broker.bankid.model.AuthResponse;
import org.keycloak.broker.bankid.model.BankidHintCodes;
import org.keycloak.broker.bankid.model.CollectResponse;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.provider.util.SimpleHttp.Response;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class SimpleBankidClient {
  private static final Logger logger = Logger.getLogger(SimpleBankidClient.class);
  public static final String PERSONAL_NUMBER = "personalNumber";
  public static final String END_USER_IP = "endUserIp";
  public static final String ORDER_REF = "orderRef";
  
  public static final String API_AUTH = "/rp/v5/auth";
  public static final String API_COLLECT = "/rp/v5/collect";
  public static final String API_CANCEL = "/rp/v5/cancel";
  
  private final HttpClient httpClient;
	private final String baseUrl;
	
	public SimpleBankidClient(HttpClient httpClient, String baseUrl) {
		this.httpClient = httpClient;
		this.baseUrl = baseUrl;
	}
	
	public AuthResponse sendAuth(String personalNumber, String endUserIp) {
		Map<String, String> requestData = new HashMap<>();
		if ( personalNumber != null ) {
			requestData.put(PERSONAL_NUMBER, personalNumber);
		}
		requestData.put(END_USER_IP, endUserIp);
		Response response = sendRequest(API_AUTH, requestData);
		try {
			return response.asJson(AuthResponse.class);
		} catch (IOException e) {
			logger.error("Failed to parse BankID response", e);
			throw new BankidClientException(BankidHintCodes.internal, e);
		}
	}
	
	public CollectResponse sendCollect(String orderRef) {
		Map<String, String> requestData = new HashMap<>();
		requestData.put(ORDER_REF, orderRef);
		try {
			Response response = sendRequest(API_COLLECT, requestData);
			CollectResponse responseData  = response.asJson(CollectResponse.class);
			// TODO: Handle when status is failed
			return responseData;
		} catch (IOException e) {
			logger.error("Failed to parse BankID response", e);
			throw new BankidClientException(BankidHintCodes.internal, e);
		}
	}

	public void sendCancel(String orderrRef) {
		Map<String, String> requestData = new HashMap<>();
		requestData.put(ORDER_REF, orderrRef);
		try {
			sendRequest(API_CANCEL, requestData);
		} catch (Exception e) {
			logger.warn("Failed cancel BankID auth request " + orderrRef, e);
		}
	}
	
	private Response sendRequest(String path, Object entity) {
		try {
			var response = SimpleHttp.doPost(this.baseUrl + path, this.httpClient).json(entity).asResponse();
			switch(response.getStatus()) {
			case 200:
					return response;
			case 400:
					return handle400Response(path, response);
			case 503:
					return handle503Response(path, response);
			default:
					return handleOtherHttpErrors(path, response);
			}
		} catch (IOException e) {
			logger.info("Failed to send request to BankID");
			throw new BankidClientException(BankidHintCodes.internal, e);
		}
	}

	private Response handleOtherHttpErrors(String path, Response resp) {
		try {
			logger.info(String.format("Request to %s failed with status code %d and payload %s", path, resp.getStatus(), resp.asString()));
		} catch (IOException e) { }
		throw new  BankidClientException(BankidHintCodes.internal);
	}

	private Response handle503Response(String path, Response resp) {
		try {
			logger.errorf("Request to %s failed with status code %d and payload %s", path, resp.getStatus(), resp.asString());
		} catch (IOException e) { }
		throw new  BankidClientException(BankidHintCodes.Maintenance);
	}

	private Response handle400Response(String path, Response resp) {
		try {
			JsonNode responseJson = resp.asJson();
			logger.info(String.format("Request to %s failed with status code %d and payload %s", path, resp.getStatus(), responseJson.toString()));
			throw new  BankidClientException(BankidHintCodes.valueOf(responseJson.get("errorCode").textValue()));
		} catch (IOException e) { 
			throw new  BankidClientException(BankidHintCodes.internal);
		}
	}
}
