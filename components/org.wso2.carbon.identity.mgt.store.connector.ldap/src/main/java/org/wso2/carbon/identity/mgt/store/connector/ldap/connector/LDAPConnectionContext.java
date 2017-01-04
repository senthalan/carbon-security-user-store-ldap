/*
 * Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreConnectorException;
import org.wso2.carbon.identity.mgt.store.connector.ldap.util.LDAPConstants;

import java.util.Hashtable;
import java.util.Map;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;



/**
 * LDAP connection context for LDAP connectors
 */

public class LDAPConnectionContext {

    private static Logger log = LoggerFactory.getLogger(LDAPConnectionContext.class);
    private Hashtable environment;

    public LDAPConnectionContext(Map<String, String> properties) throws IdentityStoreConnectorException {

        String connectionURL = properties.get(LDAPConstants.CONNECTION_URL);
        String connectionName = properties.get(LDAPConstants.CONNECTION_NAME);
        String connectionPassword = properties.get(LDAPConstants.CONNECTION_PASSWORD);

        if (log.isDebugEnabled()) {
            log.debug("Connection Name :: " + connectionName + ", Connection URL :: " + connectionURL);
        }

        environment = new Hashtable();

        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");

        if (connectionName != null) {
            environment.put(Context.SECURITY_PRINCIPAL, connectionName);
        }

        if (connectionPassword != null) {
            environment.put(Context.SECURITY_CREDENTIALS, connectionPassword);
        }

        if (connectionURL != null) {
            environment.put(Context.PROVIDER_URL, connectionURL);
        }

        environment.put("com.sun.jndi.ldap.connect.pool", "true");
        environment.put("com.sun.jndi.ldap.connect.timeout", "5000");
        environment.put("com.sun.jndi.ldap.read.timeout", "5000");

    }

    public DirContext getContext() throws IdentityStoreConnectorException {

        DirContext context = null;
        try {
                    context = new InitialDirContext(environment);

        } catch (NamingException e) {
            log.error("Error obtaining connection. " + e.getMessage(), e);
            log.error("Trying again to get connection.");
//
//            try {
//                context = new InitialDirContext(environment);
//            } catch (Exception e1) {
//                log.error("Error obtaining connection for the second time" + e.getMessage(), e);
//                throw new IdentityStoreConnectorException("Error obtaining connection. " + e.getMessage(), e);
//            }

        }
        return context;

    }

}
