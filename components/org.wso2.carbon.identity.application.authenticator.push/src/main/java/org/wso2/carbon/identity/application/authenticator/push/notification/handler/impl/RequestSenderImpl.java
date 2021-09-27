/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.push.notification.handler.impl;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.push.PushAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.push.common.PushAuthContextManager;
import org.wso2.carbon.identity.application.authenticator.push.common.impl.PushAuthContextManagerImpl;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.DeviceHandler;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.exception.PushDeviceHandlerClientException;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.exception.PushDeviceHandlerServerException;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.impl.DeviceHandlerImpl;
import org.wso2.carbon.identity.application.authenticator.push.device.handler.model.Device;
import org.wso2.carbon.identity.application.authenticator.push.dto.AuthDataDTO;
import org.wso2.carbon.identity.application.authenticator.push.exception.PushAuthenticatorException;
import org.wso2.carbon.identity.application.authenticator.push.internal.PushAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.push.notification.handler.FirebasePushNotificationSender;
import org.wso2.carbon.identity.application.authenticator.push.notification.handler.RequestSender;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import ua_parser.Client;
import ua_parser.Parser;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implements the functionality for request sender.
 */
public class RequestSenderImpl implements RequestSender {

    private static final Log log = LogFactory.getLog(RequestSenderImpl.class);

    @Override
    public void sendRequest(HttpServletRequest request, HttpServletResponse response, String deviceId, String key)
            throws PushAuthenticatorException, AuthenticationFailedException {

        Device device = getDevice(deviceId);
        PushAuthContextManager contextManager = new PushAuthContextManagerImpl();
        AuthenticationContext context = contextManager.getContext(key);

        // OB specific change to use login_hint attribute in the CIBA request object
        // as the authenticated user
        /*AuthenticatedUser user = context.getSequenceConfig().getStepMap().
                get(context.getCurrentStep() - 1).getAuthenticatedUser();*/
        AuthenticatedUser user = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(request.
                getParameter(PushAuthenticatorConstants.LOGIN_HINT));

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String serverKey = authenticatorProperties.get(PushAuthenticatorConstants.SERVER_KEY);
        String fcmUrl = authenticatorProperties.get(PushAuthenticatorConstants.FCM_URL);

        String username = user.getUserName();
        String hostname = request.getRemoteAddr();
        String serviceProviderName = context.getServiceProviderName();
        String message = username + " is requesting to log into " + serviceProviderName;
        String sessionDataKey = request.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
        String randomChallenge = UUID.randomUUID().toString();
        String pushId = device.getPushId();
        String fullName = getFullName(user);
        String organization = user.getTenantDomain();

        // OB specific change to retrieve consent data
        String consentInfo = retrieveConsent(key);

        String userOS = null;
        String userBrowser = null;
        Client client = getClient(request);
        if (client != null) {
            userOS = client.os.family;
            userBrowser = client.userAgent.family;
        }

        AuthDataDTO authDataDTO = (AuthDataDTO) context.getProperty(PushAuthenticatorConstants.CONTEXT_AUTH_DATA);
        authDataDTO.setChallenge(randomChallenge);
        context.setProperty(PushAuthenticatorConstants.CONTEXT_AUTH_DATA, authDataDTO);
        contextManager.storeContext(key, context);

        FirebasePushNotificationSender pushNotificationSender = FirebasePushNotificationSender.getInstance();
        pushNotificationSender.init(serverKey, fcmUrl);
        try {
            pushNotificationSender.sendPushNotification(deviceId, pushId, message, randomChallenge, sessionDataKey,
                    username, fullName, organization, serviceProviderName, hostname, userOS, userBrowser, consentInfo);
        } catch (AuthenticationFailedException e) {
            throw new PushAuthenticatorException("Error occurred when trying to send the push notification to device: "
                    + deviceId + ".", e);
        }
    }

    /**
     * Get the user claim values for required fields.
     *
     * @param authenticatedUser Authenticated user
     * @return Retrieved user claims
     * @throws AuthenticationFailedException if the user claims cannot be read
     */
    private Map<String, String> getUserClaimValues(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        Map<String, String> claimValues;
        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            claimValues = userStoreManager.getUserClaimValues(IdentityUtil.addDomainToName(
                            authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain()), new String[]{
                            PushAuthenticatorConstants.FIRST_NAME_CLAIM,
                            PushAuthenticatorConstants.LAST_NAME_CLAIM},
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to read user claims for user : "
                    + authenticatedUser.toFullQualifiedUsername() + ".", e);
        }
        return claimValues;
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param authenticatedUser Authenticated user.
     * @return The userRealm.
     * @throws AuthenticationFailedException Exception on authentication failure.
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
     * Get the device by the device ID.
     *
     * @param deviceId Unique ID for the device
     * @return device object
     * @throws PushAuthenticatorException if an error occurs while getting the device or if the device is not
     *                                    registered
     */
    private Device getDevice(String deviceId) throws PushAuthenticatorException {

        DeviceHandler deviceHandler = new DeviceHandlerImpl();
        try {
            return deviceHandler.getDevice(deviceId);
        } catch (PushDeviceHandlerClientException e) {
            throw new PushAuthenticatorException("Error occurred when trying to get device: " + deviceId + ".", e);
        } catch (PushDeviceHandlerServerException e) {
            String errorMessage = String
                    .format("Error occurred when trying to get device: %s. Device may not be registered.", deviceId);
            throw new PushAuthenticatorException(errorMessage, e);
        }
    }

    /**
     * Process the full name of the user by getting user claims.
     *
     * @param user Authenticated user
     * @return Full name of the user
     * @throws AuthenticationFailedException if an error occurs while getting user claims
     */
    private String getFullName(AuthenticatedUser user) throws AuthenticationFailedException {

        Map<String, String> userClaims;
        userClaims = getUserClaimValues(user);

        return userClaims.get(PushAuthenticatorConstants.FIRST_NAME_CLAIM) + " "
                + userClaims.get(PushAuthenticatorConstants.LAST_NAME_CLAIM);
    }

    /**
     * Get the client properties using the user-agent request header.
     *
     * @param request HTTP request
     * @return UA Client
     */
    private Client getClient(HttpServletRequest request) {

        String userAgentString = request.getHeader(PushAuthenticatorConstants.USER_AGENT);
        try {
            Parser uaParser = new Parser();
            return uaParser.parse(userAgentString);
        } catch (IOException e) {
            log.error("Error occurred while trying to get the user's OS or Web browser.", e);
            return null;
        }
    }

    /**
     * OB specific implementation to retrieve consent data
     * @param sessionDataKey
     * @return consent data
     * @throws PushAuthenticatorException
     */
    public String retrieveConsent(String sessionDataKey) throws PushAuthenticatorException {

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
            String consentData= null;
            try {
                consentData = IOUtils.toString(consentDataResponse.getEntity().getContent(),String.valueOf(StandardCharsets.UTF_8));
                Reader reader = new InputStreamReader( consentDataResponse.getEntity().getContent(), StandardCharsets.UTF_8 );
                int data = reader.read();
                while (data != -1) {
                    System.out.print((char) data);
                    data = reader.read();
                }
                return consentData;
            } catch (IOException e) {
                log.debug("Error in reading consent data retrieval response");
                throw new PushAuthenticatorException("Failed to read the consent data");
            }
        }
    }
}
