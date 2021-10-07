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

package org.wso2.carbon.identity.application.authenticator.push;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCache;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCacheKey;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.push.common.PushAuthContextManager;
import org.wso2.carbon.identity.application.authenticator.push.common.PushJWTValidator;
import org.wso2.carbon.identity.application.authenticator.push.common.exception.PushAuthTokenValidationException;
import org.wso2.carbon.identity.application.authenticator.push.common.impl.PushAuthContextManagerImpl;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.DeviceHandler;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.exception.PushDeviceHandlerClientException;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.exception.PushDeviceHandlerServerException;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.impl.DeviceHandlerImpl;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.model.Device;
import org.wso2.carbon.identity.application.authenticator.push.dto.AuthDataDTO;
import org.wso2.carbon.identity.application.authenticator.push.exception.PushAuthenticatorException;
import org.wso2.carbon.identity.application.authenticator.push.internal.PushAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.push.notification.handler.RequestSender;
import org.wso2.carbon.identity.application.authenticator.push.notification.handler.impl.RequestSenderImpl;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is the class that implements the push authenticator feature.
 */
public class PushAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 8272421416671799253L;
    private static final Log log = LogFactory.getLog(PushAuthenticator.class);

    @Override
    public String getFriendlyName() {

        return PushAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return request.getParameter(PushAuthenticatorConstants.PROCEED_AUTH) != null;
    }

    @Override
    public String getContextIdentifier(javax.servlet.http.HttpServletRequest request) {

        return request.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
    }

    @Override
    public String getName() {

        return PushAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        DeviceHandler deviceHandler = new DeviceHandlerImpl();
        PushAuthContextManager contextManager = new PushAuthContextManagerImpl();

        AuthenticatedUser user = getAuthenticatedUser(request);

        context.setSubject(user);
        String sessionDataKey = request.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);


        try {
            List<Device> deviceList;
            deviceList = deviceHandler.listDevices(getUserIdFromUsername(user.getUserName(), getUserRealm(user)));
            request.getSession().setAttribute(PushAuthenticatorConstants.DEVICES_LIST, deviceList);
            JSONObject object;
            JSONArray array = new JSONArray();

            for (Device device : deviceList) {
                object = new JSONObject();
                object.put(PushAuthenticatorConstants.DEVICE_ID, device.getDeviceId());
                object.put(PushAuthenticatorConstants.DEVICE_NAME, device.getDeviceName());
                object.put(PushAuthenticatorConstants.DEVICE_MODEL, device.getDeviceModel());
                object.put(PushAuthenticatorConstants.LAST_TIME_USED, device.getLastUsedTime().toString());
                array.add(object);
            }

            AuthDataDTO authDataDTO = new AuthDataDTO();
            context.setProperty(PushAuthenticatorConstants.CONTEXT_AUTH_DATA, authDataDTO);
            contextManager.storeContext(sessionDataKey, context);

            if (deviceList.size() == 1) {
                RequestSender requestSender = new RequestSenderImpl();
                String metadata = setMetadata(sessionDataKey);
                requestSender.sendRequest(request, response, deviceList.get(0).getDeviceId(), sessionDataKey, metadata);
                redirectWaitPage(response, sessionDataKey, user);
            } else if (deviceList.size() == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("User (" + user.toFullQualifiedUsername() + ") does not have any registered devices "
                            + "for push based authentication.");
                }

                redirectRetryPage(response, PushAuthenticatorConstants.NO_REGISTERED_DEVICES_PARAM,
                        PushAuthenticatorConstants.NO_REGISTERED_DEVICES_MESSAGE, user);
            } else {
                String errorMessage = String.format("Error occurred as user (%s) has more than one device registered "
                        + "for push based authentication.", user.toFullQualifiedUsername());
                log.error(errorMessage);
                redirectRetryPage(response, PushAuthenticatorConstants.DEVICES_OVER_LIMIT_PARAM,
                        PushAuthenticatorConstants.DEVICES_OVER_LIMIT_MESSAGE, user);
            }

        } catch (PushDeviceHandlerServerException e) {
            throw new AuthenticationFailedException("Error occurred when trying to redirect to the registered devices"
                    + " page. Devices were not found for user: " + user.toFullQualifiedUsername() + ".", e);
        } catch (PushAuthenticatorException e) {
            throw new AuthenticationFailedException("Error occurred when trying to get user claims for user: "
                    + user.toFullQualifiedUsername() + ".", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred when trying to get the user ID for user: "
                    + user.toFullQualifiedUsername() + ".", e);
        }

    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest, HttpServletResponse
            httpServletResponse, AuthenticationContext authenticationContext) throws AuthenticationFailedException {

        AuthenticatedUser user = authenticationContext.getSequenceConfig().
                getStepMap().get(authenticationContext.getCurrentStep() - 1).getAuthenticatedUser();

        PushAuthContextManager contextManager = new PushAuthContextManagerImpl();
        AuthenticationContext sessionContext = contextManager.getContext(httpServletRequest
                .getParameter(PushAuthenticatorConstants.SESSION_DATA_KEY));
        AuthDataDTO authDataDTO = (AuthDataDTO) sessionContext
                .getProperty(PushAuthenticatorConstants.CONTEXT_AUTH_DATA);

        String authResponseToken = authDataDTO.getAuthToken();
        String serverChallenge = authDataDTO.getChallenge();

        String deviceId = getDeviceIdFromToken(authResponseToken);
        String publicKey = getPublicKey(deviceId);

        PushJWTValidator validator = new PushJWTValidator();
        JWTClaimsSet claimsSet;
        try {
            claimsSet = validator.getValidatedClaimSet(authResponseToken, publicKey);
        } catch (PushAuthTokenValidationException e) {
            String errorMessage = String
                    .format("Error occurred when trying to validate the JWT signature from device: %s of user: %s.",
                            deviceId, user);
            throw new AuthenticationFailedException(errorMessage, e);
        }
        if (claimsSet != null) {
            if (validator.validateChallenge(claimsSet, serverChallenge, deviceId)) {
                String authStatus;
                try {
                    authStatus =
                            validator.getClaimFromClaimSet(claimsSet, PushAuthenticatorConstants.TOKEN_RESPONSE, deviceId);
                }
                catch (PushAuthTokenValidationException e){
                    String errorMessage = String.format("Error in getting claim %s from the auth response token received " +
                            "from device: %s", PushAuthenticatorConstants.TOKEN_SESSION_DATA_KEY, deviceId);
                    throw new AuthenticationFailedException(errorMessage, e);
                }

                if (authStatus.equals(PushAuthenticatorConstants.AUTH_REQUEST_STATUS_SUCCESS)) {
                    authenticationContext.setSubject(user);
                } else if (authStatus.equals(PushAuthenticatorConstants.AUTH_REQUEST_STATUS_DENIED)) {
                    redirectRetryPage(httpServletResponse, PushAuthenticatorConstants.AUTH_DENIED_PARAM,
                            PushAuthenticatorConstants.AUTH_DENIED_MESSAGE, user);
                } else {
                    String errorMessage = String.format("Authentication failed! Auth status for user" +
                            " '%s' is not available in JWT.", user.toFullQualifiedUsername());
                    throw new AuthenticationFailedException(errorMessage);
                }
            } else {
                String errorMessage = String
                        .format("Authentication failed! JWT challenge validation for device: %s of user: %s.",
                                deviceId, user);
                throw new AuthenticationFailedException(errorMessage);
            }
        } else {
            String errorMessage = String
                    .format("Authentication failed! JWT signature is not valid for device: %s of user: %s.",
                            deviceId, user.toFullQualifiedUsername());
            throw new AuthenticationFailedException(errorMessage);
        }

        try{
            contextManager.clearContext(validator.getClaimFromClaimSet(claimsSet,
                    PushAuthenticatorConstants.TOKEN_SESSION_DATA_KEY, deviceId));
        }
        catch (PushAuthTokenValidationException e){
            String errorMessage = String.format("Error in getting claim %s from the auth response token received " +
                    "from device: %s", PushAuthenticatorConstants.TOKEN_SESSION_DATA_KEY, deviceId);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        String firebaseServerKey = "Firebase Server Key";
        Property serverKeyProperty = new Property();
        serverKeyProperty.setName(PushAuthenticatorConstants.SERVER_KEY);
        serverKeyProperty.setDisplayName(firebaseServerKey);
        serverKeyProperty.setDescription("Enter the firebase server key ");
        serverKeyProperty.setDisplayOrder(0);
        serverKeyProperty.setRequired(true);
        serverKeyProperty.setConfidential(true);
        configProperties.add(serverKeyProperty);

        String fcmUrl = "Firebase url";
        Property fcmUrlProperty = new Property();
        fcmUrlProperty.setName(PushAuthenticatorConstants.FCM_URL);
        fcmUrlProperty.setDisplayName(fcmUrl);
        fcmUrlProperty.setDescription("Enter the url of firebase endpoint ");
        fcmUrlProperty.setDisplayOrder(1);
        fcmUrlProperty.setConfidential(false);
        configProperties.add(fcmUrlProperty);
        return configProperties;
    }

    /**
     * Get the authenticated user
     *
     * @param request Push authenticator HTTP request
     * @return Authenticated User
     */
    protected AuthenticatedUser getAuthenticatedUser(HttpServletRequest request){

//        String sessionDataKey = request.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
//
//        PushAuthContextManager contextManager = new PushAuthContextManagerImpl();
//        AuthenticationContext context = contextManager.getContext(sessionDataKey);
//
//        return context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1)
//                .getAuthenticatedUser();

        // In OB CIBA, only this Push Authenticator IDP is expected to be executed during the CIBA auth flow
        // Hence, the login_hint attribute in the CIBA request object is used to identify the user
        return AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(request.
                getParameter(PushAuthenticatorConstants.LOGIN_HINT));
    }

    /**
     * Get the user realm for the authenticated user.
     *
     * @param authenticatedUser Authenticated user
     * @return User realm
     * @throws AuthenticationFailedException if an error occurs when getting the user realm
     */
    private UserRealm getUserRealm(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        UserRealm userRealm = null;
        try {
            if (authenticatedUser != null) {
                String tenantDomain = authenticatedUser.getTenantDomain();
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = PushAuthenticatorServiceDataHolder.getInstance().getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred when trying to get the user realm for user: "
                    + authenticatedUser.toFullQualifiedUsername() + ".", e);
        }
        return userRealm;
    }

    /**
     * Get the user ID from the username.
     *
     * @param username username of the user
     * @param realm    user realm for the tenant
     * @return user ID
     * @throws UserStoreException userstore exception
     */
    private String getUserIdFromUsername(String username, UserRealm realm) throws UserStoreException {

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) realm.getUserStoreManager();
        return userStoreManager.getUserIDFromUserName(username);
    }


    /**
     * Derive the Device ID from the auth response token header.
     *
     * @param token Auth response token
     * @return Device ID
     * @throws AuthenticationFailedException if the token string fails to parse to JWT
     */
    protected String getDeviceIdFromToken(String token) throws AuthenticationFailedException {

        try {
            return String.valueOf(JWTParser.parse(token).getHeader()
                    .getCustomParam(PushAuthenticatorConstants.TOKEN_DEVICE_ID));
        } catch (ParseException e) {
            throw new AuthenticationFailedException("Error occurred when trying to get the device ID from the "
                    + "auth response token.", e);
        }
    }

    /**
     * Get the public key for the device by the device ID.
     *
     * @param deviceId Unique ID for the device
     * @return Public key string
     * @throws AuthenticationFailedException if an error occurs while getting the public key
     */
    protected String getPublicKey(String deviceId) throws AuthenticationFailedException {

        DeviceHandler deviceHandler = new DeviceHandlerImpl();
        try {
            return deviceHandler.getPublicKey(deviceId);
        } catch (PushDeviceHandlerServerException | PushDeviceHandlerClientException e) {
            throw new AuthenticationFailedException("Error occurred when trying to get the public key for device: "
                    + deviceId + ".");
        }
    }

    /**
     * Redirect user to device selection page.
     *
     * @param response          HTTP response
     * @param user              Authenticated user
     * @param sessionDataKey    Unique key for the session
     * @param deviceArrayString JSON array as a string
     * @throws IOException if an error occurs when redirecting to the device selection page
     */
    protected void redirectDevicesPage(HttpServletResponse response, String sessionDataKey, String deviceArrayString,
                                       AuthenticatedUser user) throws IOException, AuthenticationFailedException {

        /*
         *  Method will be required once https://github.com/wso2-incubator/identity-outbound-auth-push/issues/84
         *  is resolved.
         */
        try {
            String deviceSelectionPage = ServiceURLBuilder.create().addPath(PushAuthenticatorConstants.DEVICES_PAGE)
                    .addParameter("sessionDataKey", sessionDataKey)
                    .addParameter("devices", deviceArrayString)
                    .build().getAbsolutePublicURL();
            response.sendRedirect(deviceSelectionPage);
        } catch (URLBuilderException e) {
            String errorMessage = String.format("Error occurred when building the URL for the device selection page "
                    + "for user: %s.", user.toFullQualifiedUsername());
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Redirect the user to the wait page.
     *
     * @param response       HTTP response
     * @param sessionDataKey Unique ID for the session
     * @param user           Authenticated user
     * @throws PushAuthenticatorException if an error occurs while trying to redirect to the wait page
     */
    protected void redirectWaitPage(HttpServletResponse response, String sessionDataKey, AuthenticatedUser user)
            throws PushAuthenticatorException, AuthenticationFailedException {

        try {
            String waitPage = ServiceURLBuilder.create().addPath(PushAuthenticatorConstants.WAIT_PAGE)
                    .addParameter("sessionDataKey", sessionDataKey).build().getAbsolutePublicURL();
            response.sendRedirect(waitPage);
        } catch (IOException e) {
            String errorMessage = String.format("Error occurred when trying to to redirect user: %s to the wait page.",
                    user.toFullQualifiedUsername());
            throw new AuthenticationFailedException(errorMessage, e);
        } catch (URLBuilderException e) {
            String errorMessage = String.format("Error occurred when building the URL for the wait page for user: %s.",
                    user.toFullQualifiedUsername());
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Redirect the user to the authentication denied page.
     *
     * @param response HTTP response
     * @param status   Status for error
     * @param message  Message to be displayed in the retry page
     * @param user     Authenticated user
     * @throws AuthenticationFailedException if an error occurs while redirecting to the retry page
     */
    protected void redirectRetryPage(HttpServletResponse response, String status, String message,
                                     AuthenticatedUser user) throws AuthenticationFailedException {

        try {
            String retryPage = ServiceURLBuilder.create().addPath(PushAuthenticatorConstants.RETRY_PAGE)
                    .addParameter("status", status)
                    .addParameter("statusMsg", message)
                    .build().getAbsolutePublicURL();
            response.sendRedirect(retryPage);
        } catch (URLBuilderException e) {
            String errorMessage = String.format("Error occurred when building the URL for the retry page for user: %s.",
                    user.toFullQualifiedUsername());
            throw new AuthenticationFailedException(errorMessage, e);
        } catch (IOException e) {
            String errorMessage = String.format("Error occurred when trying to to redirect user: %s to the retry page.",
                    user.toFullQualifiedUsername());
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }




    /**
     * OB specific implementation to retrieve consent data
     * @param sessionDataKey
     * @return consent data
     * @throws PushAuthenticatorException
     */
    protected String setMetadata(String sessionDataKey) throws PushAuthenticatorException {

        PushAuthContextManager contextManager = new PushAuthContextManagerImpl();
        AuthenticationContext context = contextManager.getContext(sessionDataKey);

        // update the authentication context with required values for OB specific requirements
        try {
            String queryParams = FrameworkUtils
                    .getQueryStringWithFrameworkContextId(context.getQueryParams(), context.getCallerSessionKey(),
                            context.getContextIdentifier());
            Map<String, String> params = splitQuery(queryParams);
            handlePreConsent(context, params);
        } catch (UnsupportedEncodingException e) {
            throw new PushAuthenticatorException("Error occurred when processing the request object", e);
        }

        SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
        SessionDataCacheEntry cacheEntry = SessionDataCache.getInstance().getValueFromCache(cacheKey);
        cacheEntry.setLoggedInUser(context.getSubject());
        SessionDataCache.getInstance().addToCache(cacheKey, cacheEntry);

        // OB specific change to add context to authenticationContextCache
        // In the default push auth impl, a PushAuthContextCache is implemented and context is stored there
        // But the Identity Framework is not updated to retrieve context from PushAuthContextCache
        // Hence, this is added to store the context in AuthenticationContextCache under sessionDataKey used here
        AuthenticationContextCache.getInstance().addToCache(
                new AuthenticationContextCacheKey(sessionDataKey), new AuthenticationContextCacheEntry(context));

        return retrieveConsent(sessionDataKey);
    }

    /**
     * set attributes to context which will be required to prompt the consent page.
     *
     * @param context authentication context
     * @param  params query params
     */
    @SuppressWarnings(value = "unchecked")
    private void handlePreConsent(AuthenticationContext context, Map<String, String> params) {

        ServiceProvider serviceProvider = context.getSequenceConfig().getApplicationConfig().getServiceProvider();

        context.addEndpointParam(PushAuthenticatorConstants.LOGGED_IN_USER,
                params.get(PushAuthenticatorConstants.LOGIN_HINT));
        context.addEndpointParam(PushAuthenticatorConstants.USER_TENANT_DOMAIN,
                "@carbon.super");
        context.addEndpointParam(PushAuthenticatorConstants.REQUEST,
                params.get(PushAuthenticatorConstants.REQUEST_OBJECT));
        context.addEndpointParam(PushAuthenticatorConstants.SCOPE,
                params.get(PushAuthenticatorConstants.SCOPE));
        context.addEndpointParam(PushAuthenticatorConstants.APPLICATION, serviceProvider.getApplicationName());
        context.addEndpointParam(PushAuthenticatorConstants.CONSENT_PROMPTED, true);
        context.addEndpointParam(PushAuthenticatorConstants.AUTH_REQ_ID,
                context.getAuthenticationRequest().getRequestQueryParams().get(PushAuthenticatorConstants.NONCE)[0]);
    }

    /**
     * Returns a map of query parameters from the given query param string.
     * @param queryParamsString HTTP request query parameters
     * @return Query parameter map
     */
    protected Map<String, String> splitQuery(String queryParamsString) throws UnsupportedEncodingException {
        final Map<String, String> queryParams = new HashMap<>();
        final String[] pairs = queryParamsString.split("&");
        for (String pair : pairs) {
            final int idx = pair.indexOf("=");
            final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
            final String value =
                    idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
            queryParams.put(key, value);
        }
        return queryParams;
    }

    /**
     * Retrieve consent from OB database
     * @param sessionDataKey Session Data Key
     * @return Response of consent retrieval request
     */
    private String retrieveConsent(String sessionDataKey) throws PushAuthenticatorException {

        String hostName = ServerConfiguration.getInstance().getFirstProperty("HostName");
        int defaultPort = 9443;
        int port =  defaultPort + Integer.parseInt(ServerConfiguration.getInstance()
                .getFirstProperty("Ports.Offset"));

        String retrieveUrl = "https://" + hostName + ":" +port +
                PushAuthenticatorConstants.CONSENT_RETRIEVAL_PATH + sessionDataKey;

        ServerConfiguration.getInstance().getFirstProperty("Ports.Offset");

        String adminUsername;
        char[] adminPassword;
        try {
            RealmConfiguration realmConfiguration = CarbonContext.getThreadLocalCarbonContext().getUserRealm()
                    .getRealmConfiguration();
            adminUsername = realmConfiguration.getAdminUserName();
            adminPassword = realmConfiguration.getAdminPassword().toCharArray();
        } catch (UserStoreException e) {
            log.debug("Failed to retrieve admin credentials");
            throw new PushAuthenticatorException("Failed to retrieve admin credentials");
        }

        String credentials = adminUsername + ":" + String.valueOf(adminPassword);
        credentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet dataRequest = new HttpGet(retrieveUrl);
        dataRequest.addHeader("Authorization", "Basic " + credentials);
        HttpResponse consentDataResponse = null;
        try {
            consentDataResponse = client.execute(dataRequest);
        } catch (IOException e) {
            log.debug("Failed to retrieve consent data");
            throw new PushAuthenticatorException("Failed to retrieve consent data", e);
        }
        log.debug("HTTP response for consent retrieval" + consentDataResponse.toString());

        if (consentDataResponse.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_MOVED_TEMP &&
                consentDataResponse.getLastHeader("Location") != null) {
            log.debug("Error in consent data retrieval response");
            throw new PushAuthenticatorException("Failed to retrieve consent data");
        } else {
            String consentData;
            try {
                consentData = IOUtils.toString(consentDataResponse.getEntity().getContent(),
                        String.valueOf(StandardCharsets.UTF_8));
                return consentData;
            } catch (IOException e) {
                log.debug("Error in reading consent data retrieval response");
                throw new PushAuthenticatorException("Failed to read the consent data");
            }
        }
    }

}
