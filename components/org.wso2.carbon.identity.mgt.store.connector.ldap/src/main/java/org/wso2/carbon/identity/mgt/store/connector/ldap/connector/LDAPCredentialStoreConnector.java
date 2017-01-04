/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.mgt.store.connector.ldap.connector;

import org.wso2.carbon.identity.mgt.connector.CredentialStoreConnector;
import org.wso2.carbon.identity.mgt.connector.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreConnectorException;

import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

/**
 * LDAP connector for the credential store.
 *
 * @since 1.0.0
 */

public class LDAPCredentialStoreConnector implements CredentialStoreConnector {

    private String credentialStoreId;
    private CredentialStoreConnectorConfig credentialStoreConfig;

    @Override
    public void init(CredentialStoreConnectorConfig credentialStoreConnectorConfig)
            throws CredentialStoreConnectorException {
        this.credentialStoreConfig = credentialStoreConnectorConfig;
        this.credentialStoreId = credentialStoreConnectorConfig.getConnectorId();

    }

    @Override
    public String getCredentialStoreConnectorId() {
        return credentialStoreId;
    }

    @Override
    public void authenticate(String s, Callback[] callbacks)
            throws CredentialStoreConnectorException, AuthenticationFailure {

    }

    @Override
    public boolean canHandle(Callback[] callbacks) {

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean canStore(Callback[] callbacks) {
        return false;
    }

    @Override
    public CredentialStoreConnectorConfig getCredentialStoreConfig() {
        return credentialStoreConfig;
    }

    @Override
    public String addCredential(List<Callback> list) throws CredentialStoreConnectorException {
        return null;
    }

    @Override
    public Map<String, String> addCredentials(Map<String, List<Callback>> map)
            throws CredentialStoreConnectorException {
        return null;
    }

    @Override
    public String updateCredentials(String s, List<Callback> list) throws CredentialStoreConnectorException {
        return null;
    }

    @Override
    public String updateCredentials(String s, List<Callback> list, List<Callback> list1)
            throws CredentialStoreConnectorException {
        return null;
    }

    @Override
    public void deleteCredential(String s) throws CredentialStoreConnectorException {

    }
}
