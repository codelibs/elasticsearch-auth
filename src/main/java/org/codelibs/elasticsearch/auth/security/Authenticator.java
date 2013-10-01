package org.codelibs.elasticsearch.auth.security;

import org.elasticsearch.rest.RestRequest;

public interface Authenticator {

    boolean authenticate(RestRequest request, String[] roles);

    String login(RestRequest request);

}
