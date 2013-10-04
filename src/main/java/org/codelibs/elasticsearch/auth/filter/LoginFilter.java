package org.codelibs.elasticsearch.auth.filter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.codelibs.elasticsearch.auth.security.Authenticator;
import org.codelibs.elasticsearch.auth.service.AuthService;
import org.codelibs.elasticsearch.auth.util.ResponseUtil;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;

public class LoginFilter extends RestFilter {
    private static final ESLogger logger = Loggers.getLogger(LoginFilter.class);

    private Method[] methods = new Method[] { Method.POST, Method.PUT };

    private String loginPath = "/login";

    private Map<String, Authenticator> authenticatorMap;

    private AuthService authService;

    public LoginFilter(final AuthService authService,
            final Map<String, Authenticator> authenticatorMap) {
        this.authService = authService;
        this.authenticatorMap = authenticatorMap;
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        final String rawPath = request.rawPath();
        if (rawPath.equals(loginPath)) {
            for (final Method method : methods) {
                if (method == request.method()) {
                    final List<String> roleList = new ArrayList<String>();
                    for (final Map.Entry<String, Authenticator> entry : authenticatorMap
                            .entrySet()) {
                        final String[] roles = entry.getValue().login(request);
                        if (roles != null) {
                            for (final String role : roles) {
                                roleList.add(role);
                            }
                        }
                    }

                    String token = null;
                    if (!roleList.isEmpty()) {
                        token = authService.createToken(roleList);
                    }

                    if (logger.isDebugEnabled()) {
                        logger.debug("Token " + token + " is generated.");
                    }

                    if (token == null) {
                        ResponseUtil.send(request, channel,
                                RestStatus.BAD_REQUEST, "message",
                                "Invalid username or password.");
                    } else {
                        ResponseUtil.send(request, channel, RestStatus.OK,
                                "token", token);
                    }
                    return;
                }
            }
            ResponseUtil
                    .send(request, channel, RestStatus.BAD_REQUEST, "message",
                            "Unsupported HTTP method for the login process.");
            return;
        }
        filterChain.continueProcessing(request, channel);
    }

    public void setLoginPath(final String loginPath) {
        this.loginPath = loginPath;
    }

    public void setHttpMethods(final Method[] method) {
        methods = method;
    }

}
