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

package org.wso2.carbon.identity.application.authenticator.push.notification.handler;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.push.exception.PushAuthenticatorException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Processes auth request to be sent as push notifications.
 */
public interface RequestSender {

    /**
     * Send the authentication request to the mobile app using FCM.
     *
     * @param request  HTTP Request
     * @param response HTTP Response
     * @param deviceId Device ID of the authenticating device
     * @param key      Session Data Key
     * @throws PushAuthenticatorException if an error occurs while preparing the push notification
     */
    void sendRequest(HttpServletRequest request, HttpServletResponse response, String deviceId, String key, String metadata)
            throws PushAuthenticatorException, AuthenticationFailedException;
}
