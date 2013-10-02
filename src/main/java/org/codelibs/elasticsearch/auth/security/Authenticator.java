package org.codelibs.elasticsearch.auth.security;

import java.util.Map;

import org.elasticsearch.rest.RestRequest;

public interface Authenticator {

    boolean authenticate(RestRequest request, String[] roles);

    Map<String, Object> login(RestRequest request);

}
