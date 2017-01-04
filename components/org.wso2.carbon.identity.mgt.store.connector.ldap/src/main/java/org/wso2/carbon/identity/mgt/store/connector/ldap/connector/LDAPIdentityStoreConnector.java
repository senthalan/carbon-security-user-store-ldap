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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.mgt.connector.Attribute;
import org.wso2.carbon.identity.mgt.connector.IdentityStoreConnector;
import org.wso2.carbon.identity.mgt.connector.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.store.connector.ldap.util.JNDIUtil;
import org.wso2.carbon.identity.mgt.store.connector.ldap.util.LDAPConstants;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

/**
 * LDAP connector for the identity store.
 *
 * @since 1.0.0
 */

public class LDAPIdentityStoreConnector implements IdentityStoreConnector {
    private static Logger log = LoggerFactory.getLogger(LDAPIdentityStoreConnector.class);

    protected IdentityStoreConnectorConfig identityStoreConfig;
    protected String identityStoreId;
    protected LDAPConnectionContext connectionSource = null;
    protected Map<String, String> properties;

    protected static final String EMPTY_ATTRIBUTE_STRING = "";
    public static final String ATTR_NAME_CN = "cn";
    public static final String ATTR_NAME_SN = "sn";
    private static final String PROPERTY_REFERRAL_IGNORE = "ignore";
    private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";


    @Override
    public void init(IdentityStoreConnectorConfig identityStoreConnectorConfig)
            throws IdentityStoreConnectorException {
        this.properties = identityStoreConnectorConfig.getProperties();
        this.identityStoreId = identityStoreConnectorConfig.getConnectorId();
        this.identityStoreConfig = identityStoreConnectorConfig;
        connectionSource = new LDAPConnectionContext(properties);

    }

    @Override
    public String getIdentityStoreConnectorId() {
        return identityStoreId;
    }

    @Override
    public String getConnectorUserId(String s, String s1)
            throws UserNotFoundException, IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<String> listConnectorUserIds(String s, String s1, int i, int i1)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<String> listConnectorUserIdsByPattern(String s, String s1, int i, int i1)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public int getUserCount() throws IdentityStoreConnectorException {
        return 0;
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userId) throws IdentityStoreConnectorException {
//        public Map<String, String> getUserPropertyValues(String userName, String[] propertyNames,
//                String profileName) throws UserStoreException {

        String userAttributeSeparator = ",";
        String userDN = null;
//            LdapName ldn = (LdapName)userCache.get(userName);
//        LdapName ldn = null;
//
//
//        if (ldn == null) {
        // read list of patterns from user-mgt.xml
        String patterns = properties.get(LDAPConstants.USER_DN_PATTERN);

        if (patterns != null && !patterns.isEmpty()) {

            if (log.isDebugEnabled()) {
                log.debug("Using User DN Patterns " + patterns);
            }

            if (patterns.contains("#")) {
                userDN = getNameInSpaceForUserName(userId);
            } else {
                userDN = MessageFormat.format(patterns, userId);
            }
        }
//        } else {
//            userDN = ldn.toString();
//        }

//            Map<String, String> values = new HashMap<String, String>();
        List<Attribute> userAttributes = new ArrayList<>();
        // if user name contains domain name, remove domain name

        DirContext dirContext = this.connectionSource.getContext();
        String userSearchFilter = properties.get(LDAPConstants.USER_NAME_SEARCH_FILTER);
        String searchFilter = userSearchFilter.replace("?", userId);

        NamingEnumeration<?> answer = null;
        NamingEnumeration<?> attrs = null;
        try {
            if (userDN != null) {
                SearchControls searchCtls = new SearchControls();
                searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//                    if (propertyNames != null && propertyNames.length > 0) {
//                        searchCtls.setReturningAttributes(propertyNames);
//                    }
//                    if (log.isDebugEnabled()) {
//                        try {
//                            log.debug("Searching for user with SearchFilter: " + searchFilter
// + " in SearchBase: " + dirContext.getNameInNamespace());
//                        } catch (NamingException e) {
//                            log.debug("Error while getting DN of search base", e);
//                        }
//                        if (propertyNames == null) {
//                            log.debug("No attributes requested");
//                        } else {
//                            for (String attribute : propertyNames) {
//                                log.debug("Requesting attribute :" + attribute);
//                            }
//                        }
//                    }
                try {
//                        answer = dirContext.search(escapeDNForSearch(userDN), searchFilter, searchCtls);
                    answer = dirContext.search(userDN, searchFilter, searchCtls);

                } catch (PartialResultException e) {
                    // can be due to referrals in AD. so just ignore error
                    String errorMessage = "Error occurred while searching directory context for user : "
                            + userDN + " searchFilter : " + searchFilter;
                    if (isIgnorePartialResultException()) {
                        if (log.isDebugEnabled()) {
                            log.debug(errorMessage, e);
                        }
                    } else {
                        throw new IdentityStoreConnectorException(errorMessage, e);
                    }
                } catch (NamingException e) {
                    String errorMessage = "Error occurred while searching directory context for user : "
                            + userDN + " searchFilter : " + searchFilter;
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage, e);
                    }
                    throw new IdentityStoreConnectorException(errorMessage, e);
                }
//                } else {
//                    answer = this.searchForUser(searchFilter, propertyNames, dirContext);
            }

            String[] propertyNames = {"cn", "givenName"};
            if (answer != null) {
                while (answer.hasMoreElements()) {
                    SearchResult sr = (SearchResult) answer.next();
                    Attributes attributes = sr.getAttributes();
                    if (attributes != null) {
                        for (String name : propertyNames) {
                            if (name != null) {

                                javax.naming.directory.Attribute attribute = attributes.get(name);
                                if (attribute != null) {
                                    StringBuffer attrBuffer = new StringBuffer();
                                    for (attrs = attribute.getAll(); attrs.hasMore(); ) {
                                        Object attObject = attrs.next();
                                        String attr = null;
                                        if (attObject instanceof String) {
                                            attr = (String) attObject;
                                        } else if (attObject instanceof byte[]) {
                                            // return canonical representation of UUIDs or
                                            // base64 encoded string of other binary data
                                            // Active Directory attribute: objectGUID
                                            // RFC 4530 attribute: entryUUID
                                            final byte[] bytes = (byte[]) attObject;
                                            if (bytes.length == 16 && name.endsWith("UID")) {
                                                // objectGUID byte order is not big-endian
                                                // https://msdn.microsoft.com/en-us/library/aa373931%28v=vs.85%29.aspx
                                                // https://community.oracle.com/thread/1157698
                                                if (name.equals("objectGUID")) {
                                                    // bytes[0] <-> bytes[3]
                                                    byte swap = bytes[3];
                                                    bytes[3] = bytes[0];
                                                    bytes[0] = swap;
                                                    // bytes[1] <-> bytes[2]
                                                    swap = bytes[2];
                                                    bytes[2] = bytes[1];
                                                    bytes[1] = swap;
                                                    // bytes[4] <-> bytes[5]
                                                    swap = bytes[5];
                                                    bytes[5] = bytes[4];
                                                    bytes[4] = swap;
                                                    // bytes[6] <-> bytes[7]
                                                    swap = bytes[7];
                                                    bytes[7] = bytes[6];
                                                    bytes[6] = swap;
                                                }
                                                final java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(bytes);
                                                attr = new java.util.UUID(bb.getLong(), bb.getLong()).toString();
                                            } else {
                                                attr = Base64.getEncoder().encodeToString((byte[]) attObject);
                                            }
                                        }

                                        if (attr != null && attr.trim().length() > 0) {
                                            String attrSeparator = properties.get(MULTI_ATTRIBUTE_SEPARATOR);
                                            if (attrSeparator != null && !attrSeparator.trim().isEmpty()) {
                                                userAttributeSeparator = attrSeparator;
                                            }
                                            attrBuffer.append(attr + userAttributeSeparator);
                                        }
                                        String value = attrBuffer.toString();

                                /*
                                 * Length needs to be more than userAttributeSeparator.length() for a valid
                                 * attribute, since we
                                 * attach userAttributeSeparator
                                 */
                                        if (value.trim().length() > userAttributeSeparator.length()) {
                                            value = value.substring(0,
                                                    value.length() - userAttributeSeparator.length());
                                            Attribute attribute2 = new Attribute();
                                            attribute2.setAttributeName(name);
                                            attribute2.setAttributeValue(value);
                                            userAttributes.add(attribute2);
                                        }

                                    }
                                }
                            }
                        }
                    }
                }
            }

        } catch (NamingException e) {
            String errorMessage = "Error occurred while getting user property values for user : ";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreConnectorException(errorMessage, e);
        } finally {
            // close the naming enumeration and free up resources
            JNDIUtil.closeNamingEnumeration(attrs);
            JNDIUtil.closeNamingEnumeration(answer);
            // close directory context
            JNDIUtil.closeContext(dirContext);
        }
        return userAttributes;
    }

    /**
     * @param userName
     * @return
     * @throws IdentityStoreConnectorException
     */
    protected String getNameInSpaceForUserName(String userName) throws IdentityStoreConnectorException {
        // check the cache first
//        LdapName ldn = (LdapName)userCache.get(userName);
//        LdapName ldn = null;
//        if (ldn != null) {
//            return ldn.toString();
//        }

        String searchBase = null;
        String userSearchFilter = properties.get(LDAPConstants.USER_NAME_SEARCH_FILTER);
//        userSearchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));
        userSearchFilter = userSearchFilter.replace("?", userName);
        String userDNPattern = properties.get(LDAPConstants.USER_DN_PATTERN);
        if (userDNPattern != null && userDNPattern.trim().length() > 0) {
            String[] patterns = userDNPattern.split("#");
            for (String pattern : patterns) {
//                searchBase = MessageFormat.format(pattern, escapeSpecialCharactersForDN(userName));
                searchBase = MessageFormat.format(pattern, userName);

                String userDN = getNameInSpaceForUserName(userName, searchBase, userSearchFilter);
                // check in another DN pattern
                if (userDN != null) {
                    return userDN;
                }
            }
        }

        searchBase = properties.get(LDAPConstants.USER_SEARCH_BASE);

        return getNameInSpaceForUserName(userName, searchBase, userSearchFilter);

    }

    /**
     * @param userName
     * @param searchBase
     * @param searchFilter
     * @return
     * @throws IdentityStoreConnectorException
     */
    protected String getNameInSpaceForUserName(String userName, String searchBase, String searchFilter)
            throws IdentityStoreConnectorException {
        boolean debug = log.isDebugEnabled();

//        if (userCache.get(userName) != null) {
//            return userCache.get(userName).toString();
//        }

        String userDN = null;

        DirContext dirContext = this.connectionSource.getContext();
        NamingEnumeration<SearchResult> answer = null;
        try {
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            if (log.isDebugEnabled()) {
                try {
                    log.debug("Searching for user with SearchFilter: " + searchFilter
                            + " in SearchBase: " + dirContext.getNameInNamespace());
                } catch (NamingException e) {
                    log.debug("Error while getting DN of search base", e);
                }
            }
            SearchResult userObj = null;
            String[] searchBases = searchBase.split("#");
            for (String base : searchBases) {
//                answer = dirContext.search(escapeDNForSearch(base), searchFilter, searchCtls);
                answer = dirContext.search(base, searchFilter, searchCtls);

                if (answer.hasMore()) {
                    userObj = (SearchResult) answer.next();
                    if (userObj != null) {
                        //no need to decode since , if decoded the whole string, can't be encoded again
                        //eg CN=Hello\,Ok=test\,test, OU=Industry
                        userDN = userObj.getNameInNamespace();
                        break;
                    }
                }
            }
            if (userDN != null) {
                LdapName ldn = new LdapName(userDN);
//                userCache.put(userName, ldn);
            }
            if (debug) {
                log.debug("Name in space for " + userName + " is " + userDN);
            }
        } catch (Exception e) {
            log.debug(e.getMessage(), e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }
        return userDN;
    }

    private boolean isIgnorePartialResultException() {

        if (PROPERTY_REFERRAL_IGNORE.equals(properties.get(LDAPConstants.PROPERTY_REFERRAL))) {
            return true;
        }
        return false;
    }

    @Override
    public List<Attribute> getUserAttributeValues(String s, List<String> list)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public int getGroupCount() throws IdentityStoreConnectorException {
        return 0;
    }

    @Override
    public String getConnectorGroupId(String s, String s1)
            throws GroupNotFoundException, IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<String> listConnectorGroupIds(String s, String s1, int i, int i1)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<String> listConnectorGroupIdsByPattern(String s, String s1, int i, int i1)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String s) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String s, List<String> list)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public boolean isUserInGroup(String s, String s1) throws IdentityStoreConnectorException {
        return false;
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreConnectorException {
        return false;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig() {
        return identityStoreConfig;
    }

    @Override
    public String addUser(List<Attribute> list) throws IdentityStoreConnectorException {

        DirContext dirContext = getSearchBaseDirectoryContext();
        /* getting add user basic attributes */
        BasicAttributes basicAttributes = getAddUserBasicAttributes();

//        BasicAttribute userPassword = new BasicAttribute("userPassword");
//        String passwordHashMethod = this.realmConfig.getUserStoreProperty(PASSWORD_HASH_METHOD);
//        if (passwordHashMethod == null) {
//            passwordHashMethod = realmConfig.getUserStoreProperty("passwordHashMethod");
//        }
//        userPassword.add(UserCoreUtil.getPasswordToStore((String) credential, passwordHashMethod, kdcEnabled));
//        basicAttributes.put(userPassword);
        setUserClaims(list, basicAttributes);
        String userName = null;
        try {
            userName = (String) basicAttributes.get(LDAPConstants.USER_NAME_ATTRIBUTE).get();
        } catch (NamingException e) {
            log.error(e.getMessage());
        }

        try {

            NameParser ldapParser = dirContext.getNameParser("");
            Name compoundName = ldapParser.parse(properties.get(
                    LDAPConstants.USER_NAME_ATTRIBUTE) + "=" + userName);

            if (log.isDebugEnabled()) {
                log.debug("Binding user: " + compoundName);
            }
            dirContext.bind(compoundName, null, basicAttributes);
        } catch (NamingException e) {
            String errorMessage = "Cannot access the directory context or "
                    + "user already exists in the system for user :" + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreConnectorException(errorMessage, e);
        } finally {
            JNDIUtil.closeContext(dirContext);
        }
        return userName;
    }

    /**
     * Returns a BasicAttributes object with basic required attributes
     *
     * @return
     */
    protected BasicAttributes getAddUserBasicAttributes() {
        BasicAttributes basicAttributes = new BasicAttributes(true);
        String userEntryObjectClassProperty = properties.get(LDAPConstants.USER_ENTRY_OBJECT_CLASS);
        BasicAttribute objectClass = new BasicAttribute(LDAPConstants.OBJECT_CLASS_NAME);
        String[] objectClassHierarchy = userEntryObjectClassProperty.split("/");
        for (String userObjectClass : objectClassHierarchy) {
            if (userObjectClass != null && !userObjectClass.trim().equals("")) {
                objectClass.add(userObjectClass.trim());
            }
        }
        // If KDC is enabled we have to set KDC specific object classes also
//        if (kdcEnabled) {
//            // Add Kerberos specific object classes
//            objectClass.add("krb5principal");
//            objectClass.add("krb5kdcentry");
//            objectClass.add("subschema");
//        }
        basicAttributes.put(objectClass);
        //TODO no need to treat user name as special attribute
//        BasicAttribute userNameAttribute = new BasicAttribute(properties.get(LDAPConstants.USER_NAME_ATTRIBUTE));
//        userNameAttribute.add(userName);
//        basicAttributes.put(userNameAttribute);

//        if (kdcEnabled) {
//            CarbonContext cc = CarbonContext.getThreadLocalCarbonContext();
//            if (cc != null) {
//                String tenantDomainName = cc.getTenantDomain();
//                if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomainName)) {
//                    userName = userName + UserCoreConstants.PRINCIPAL_USERNAME_SEPARATOR +
//                            tenantDomainName;
//                } else {
//                    userName = userName + UserCoreConstants.PRINCIPAL_USERNAME_SEPARATOR +
//                            MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
//                }
//            }
//
//            String principal = userName + "@" + this.getRealmName();
//
//            BasicAttribute principalAttribute = new BasicAttribute(KRB5_PRINCIPAL_NAME_ATTRIBUTE);
//            principalAttribute.add(principal);
//            basicAttributes.put(principalAttribute);
//
//            BasicAttribute versionNumberAttribute = new BasicAttribute(
//                    KRB5_KEY_VERSION_NUMBER_ATTRIBUTE);
//            versionNumberAttribute.add("0");
//            basicAttributes.put(versionNumberAttribute);
//        }
        return basicAttributes;
    }

    /**
     * Sets the set of claims provided at adding users
     *
     * @param attributeList
     * @param basicAttributes
     * @throws IdentityStoreConnectorException
     */
    protected void setUserClaims(List<Attribute> attributeList, BasicAttributes basicAttributes)
            throws IdentityStoreConnectorException {
        BasicAttribute claim;
        String userName = null;

        log.debug("Processing user claims");
        // we keep boolean values to know whether compulsory attributes 'sn' and 'cn' are set during setting claims.

        boolean isSNExists = false;
        boolean isCNExists = false;
        for (Attribute attribute : attributeList) {
            if (EMPTY_ATTRIBUTE_STRING.equals(attribute.getAttributeValue())) {
                continue;
            }
            if (LDAPConstants.USER_NAME_ATTRIBUTE.equals(attribute.getAttributeName())) {
                userName = attribute.getAttributeValue();
            }
            if (ATTR_NAME_CN.equals(attribute.getAttributeName())) {
                isCNExists = true;
            } else if (ATTR_NAME_SN.equals(attribute.getAttributeName())) {
                isSNExists = true;
            }
            claim = new BasicAttribute(attribute.getAttributeName());
            claim.add(attribute.getAttributeValue());
            basicAttributes.put(claim);
        }


        // If required attributes cn, sn are not set during claim mapping,
        // set them as user names

        if (!isCNExists) {
            BasicAttribute cn = new BasicAttribute("cn");
            //TODO Implement escape logics
//            cn.add(escapeSpecialCharactersForDNWithStar(userName));
            cn.add(userName);
            basicAttributes.put(cn);
        }

        if (!isSNExists) {
            BasicAttribute sn = new BasicAttribute("sn");
//            sn.add(escapeSpecialCharactersForDNWithStar(userName));
            sn.add(userName);
            basicAttributes.put(sn);
        }
    }

    @Override
    public Map<String, String> addUsers(Map<String, List<Attribute>> map)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public String updateUserAttributes(String s, List<Attribute> list)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public String updateUserAttributes(String s, List<Attribute> list, List<Attribute> list1)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public void deleteUser(String s) throws IdentityStoreConnectorException {

    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list) throws IdentityStoreConnectorException {

    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list, List<String> list1)
            throws IdentityStoreConnectorException {

    }

    @Override
    public String addGroup(List<Attribute> list) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public Map<String, String> addGroups(Map<String, List<Attribute>> map)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public String updateGroupAttributes(String s, List<Attribute> list)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public String updateGroupAttributes(String s, List<Attribute> list, List<Attribute> list1)
            throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public void deleteGroup(String s) throws IdentityStoreConnectorException {

    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list) throws IdentityStoreConnectorException {

    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list, List<String> list1)
            throws IdentityStoreConnectorException {

    }

    @Override
    public void removeAddedUsersInAFailure(List<String> list) throws IdentityStoreConnectorException {

    }

    @Override
    public void removeAddedGroupsInAFailure(List<String> list) throws IdentityStoreConnectorException {

    }

    protected DirContext getSearchBaseDirectoryContext() throws IdentityStoreConnectorException {
        DirContext mainDirContext = this.connectionSource.getContext();
        // assume first search base in case of multiple definitions
        String searchBase = properties.get(LDAPConstants.USER_SEARCH_BASE).split("#")[0];
        try {
            return (DirContext) mainDirContext.lookup(searchBase);
        } catch (NamingException e) {
            String errorMessage = "Can not access the directory context or"
                    + "user already exists in the system";
            throw new IdentityStoreConnectorException(errorMessage, e);
        } finally {
            JNDIUtil.closeContext(mainDirContext);
        }
    }
}
