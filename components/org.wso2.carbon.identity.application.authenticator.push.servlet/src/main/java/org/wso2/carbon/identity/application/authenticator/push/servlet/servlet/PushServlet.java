/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.carbon.identity.application.authenticator.push.servlet.servlet;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.push.common.PushAuthContextManager;
import org.wso2.carbon.identity.application.authenticator.push.common.PushJWTValidator;
import org.wso2.carbon.identity.application.authenticator.push.common.exception.PushAuthTokenValidationException;
import org.wso2.carbon.identity.application.authenticator.push.common.impl.PushAuthContextManagerImpl;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.DeviceHandler;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.exception.PushDeviceHandlerClientException;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.exception.PushDeviceHandlerServerException;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.impl.DeviceHandlerImpl;
import org.wso2.carbon.identity.application.authenticator.push.dto.AuthDataDTO;
import org.wso2.carbon.identity.application.authenticator.push.servlet.PushServletConstants;
import org.wso2.carbon.identity.application.authenticator.push.servlet.store.PushDataStore;

import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.services.IdentityEventService;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for handling authentication requests sent from mobile device.
 */
public class PushServlet extends HttpServlet {

    private static final long serialVersionUID = -2050679246736808648L;
    private static final Log log = LogFactory.getLog(PushServlet.class);
    private final PushDataStore pushDataStoreInstance = PushDataStore.getInstance();
    private static final String SESSION_DATA_KEY = "sessionDataKey";
    private static final String LOGIN_STATE = "loginState";
    private static final String CUSTOM_EVENT = "CUSTOM_EVENT";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        handleMobileResponse(request, response);
    }

    /**
     * Handles authentication request received from mobile app.
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @throws IOException
     */
    private void handleMobileResponse(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        JsonObject json = new JsonParser().parse(request.getReader().readLine()).getAsJsonObject();
        String token = json.get(PushServletConstants.AUTH_RESPONSE).getAsString();

        if (StringUtils.isEmpty(token)) {
            if (log.isDebugEnabled()) {
                log.debug(PushServletConstants.ErrorMessages.ERROR_CODE_AUTH_RESPONSE_TOKEN_NOT_FOUND.toString());
            }

            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    PushServletConstants.ErrorMessages.ERROR_CODE_AUTH_RESPONSE_TOKEN_NOT_FOUND.toString());
        } else {
            String deviceId = getDeviceIdFromToken(token);
            String sessionDataKey = getSessionDataKeyFromToken(token, deviceId);

            if (StringUtils.isEmpty(sessionDataKey)) {
                String errorMessage = String.format(
                        PushServletConstants.ErrorMessages.ERROR_CODE_SESSION_DATA_KEY_NOT_FOUND.toString(), deviceId);

                if (log.isDebugEnabled()) {
                    log.debug(errorMessage);
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, errorMessage);
            } else {
                addToContext(sessionDataKey, token);
                String status = PushServletConstants.Status.COMPLETED.name();
                pushDataStoreInstance.updateAuthStatus(sessionDataKey, status);

                HashMap<String, Object> properties = new HashMap<>();

                properties.put(LOGIN_STATE, "success");
                properties.put(SESSION_DATA_KEY, sessionDataKey);

                // Invoke a custom event to complete the authorization
                Event sampleEvent = new Event(CUSTOM_EVENT, properties);
                if (log.isDebugEnabled()) {
                    log.debug("Invoking the custom event to complete the authorization flow");
                }
                IdentityEventService identityEventService =
                        (IdentityEventService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                                .getOSGiService(IdentityEventService.class, null);

                try {
                    identityEventService.handleEvent(sampleEvent);
                } catch (IdentityEventException e) {
                    log.error("Auth error - failed to invoke the event");
                }
                response.setStatus(HttpServletResponse.SC_ACCEPTED);

                if (log.isDebugEnabled()) {
                    log.debug("Completed processing auth response from mobile app.");
                }
            }
        }
    }

    /**
     * Derive the Device ID from the auth response token header.
     *
     * @param token Auth response token
     * @return Device ID
     * @throws ServletException if the token string fails to parse to JWT
     */
    private String getDeviceIdFromToken(String token) throws ServletException {

        try {
            return String.valueOf(JWTParser.parse(token).getHeader().getCustomParam(
                    PushServletConstants.TOKEN_DEVICE_ID));
        } catch (ParseException e) {
            throw new ServletException(PushServletConstants
                    .ErrorMessages.ERROR_CODE_GET_DEVICE_ID_FAILED.toString(), e);
        }
    }

    /**
     * Derive the SessionDataKey from the auth response token.
     *
     * @param token    Auth response token
     * @param deviceId Unique ID of the device trying to authenticate
     * @return SessionDataKey
     * @throws ServletException if the auth response token fails to parse to JWT or the public key for the device
     *                          is not retrieved or if the token is not valid
     */
    private String getSessionDataKeyFromToken(String token, String deviceId) throws ServletException {

        DeviceHandler deviceHandler = new DeviceHandlerImpl();
        PushJWTValidator validator = new PushJWTValidator();

        try {
            String publicKey = deviceHandler.getPublicKey(deviceId);
            JWTClaimsSet claimsSet = validator.getValidatedClaimSet(token, publicKey);
            return claimsSet.getStringClaim(PushServletConstants.TOKEN_SESSION_DATA_KEY);
        } catch (PushDeviceHandlerServerException | PushDeviceHandlerClientException e) {
            String errorMessage = String.format(PushServletConstants
                    .ErrorMessages.ERROR_CODE_GET_PUBLIC_KEY_FAILED.toString(), deviceId);
            throw new ServletException(errorMessage);
        } catch (PushAuthTokenValidationException e) {
            String errorMessage = String.format(PushServletConstants
                    .ErrorMessages.ERROR_CODE_TOKEN_VALIDATION_FAILED.toString(), deviceId);
            throw new ServletException(errorMessage);
        } catch (ParseException e) {
            throw new ServletException(PushServletConstants.ErrorMessages.ERROR_CODE_PARSE_JWT_FAILED.toString());
        }
    }

    /**
     * Add the received auth response token to the authentication context.
     *
     * @param sessionDataKey Unique key to identify the session
     * @param token          Auth response token
     */
    private void addToContext(String sessionDataKey, String token) {

        PushAuthContextManager contextManager = new PushAuthContextManagerImpl();
        AuthenticationContext context = contextManager.getContext(sessionDataKey);

        AuthDataDTO authDataDTO = (AuthDataDTO) context.getProperty(PushServletConstants.AUTH_DATA);
        authDataDTO.setAuthToken(token);
        context.setProperty(PushServletConstants.AUTH_DATA, authDataDTO);
        contextManager.storeContext(sessionDataKey, context);
    }

}
