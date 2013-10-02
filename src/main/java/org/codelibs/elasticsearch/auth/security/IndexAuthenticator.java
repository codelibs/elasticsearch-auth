package org.codelibs.elasticsearch.auth.security;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.codec.digest.DigestUtils;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.rest.RestRequest;

public class IndexAuthenticator implements Authenticator {
    protected Client client;

    private String authIndex = "auth";

    private String userType = "user";

    private String authTokenIndex = "auth";

    private String tokenType = "token";

    private String usernameKey = "username";

    private String passwordKey = "password";

    private String tokenKey = "token";

    public IndexAuthenticator(final Client client) {
        this.client = client;
    }

    @Override
    public boolean authenticate(final RestRequest request, final String[] roles) {
        final String token = request.param(tokenKey);
        if (token != null) {
            final GetResponse response = client
                    .prepareGet(authTokenIndex, tokenType, token).execute()
                    .actionGet();
            final Map<String, Object> sourceMap = response.getSource();
            final String[] tokenRoles = (String[]) sourceMap.get("roles");
            for (final String role : roles) {
                for (final String tokenRole : tokenRoles) {
                    if (role.equals(tokenRole)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override
    public Map<String, Object> login(final RestRequest request) {
        final String username = request.param(usernameKey);
        final String password = request.param(passwordKey);
        if (username == null) {
            return null;
        }

        final GetResponse response = client
                .prepareGet(authIndex, userType, username).execute()
                .actionGet();
        final Map<String, Object> sourceMap = response.getSource();
        final String hash = (String) sourceMap.get("password");
        if (hash != null && hash.equals(hashPassword(password))) {
            final String[] roles = (String[]) sourceMap.get("roles");
            final String token = generateToken();
            final Map<String, Object> tokenMap = new HashMap<String, Object>();
            tokenMap.put("roles", roles);
            client.prepareIndex(authTokenIndex, tokenType, token)
                    .setSource(sourceMap).setRefresh(true).execute()
                    .actionGet();
            final Map<String, Object> resultMap = new HashMap<String, Object>();
            resultMap.put("status", "ok");
            resultMap.put("token", token);
            return resultMap;
        }
        return generateError("error", 400, "Invalid username or password.");
    }

    protected Map<String, Object> generateError(final String status,
            final int code, final String message) {
        final Map<String, Object> resultMap = new HashMap<String, Object>();
        resultMap.put("status", status);
        resultMap.put("code", code);
        resultMap.put("message", message);
        return resultMap;
    }

    protected String generateToken() {
        return UUID.randomUUID().toString();
    }

    protected String hashPassword(final String password) {
        if (password == null) {
            return null;
        }
        return DigestUtils.sha256Hex(password);
    }

}
