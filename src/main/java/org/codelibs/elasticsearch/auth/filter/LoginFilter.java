package org.codelibs.elasticsearch.auth.filter;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

import org.codelibs.elasticsearch.auth.security.Authenticator;
import org.codelibs.elasticsearch.auth.service.AuthService;
import org.codelibs.elasticsearch.auth.util.ResponseUtil;
import org.elasticsearch.action.ActionListener;
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
                    final Map<String, String> roleMap = new ConcurrentHashMap<String, String>();
                    final Map<String, Authenticator> authMap = authenticatorMap;
                    final CountDownLatch latch = new CountDownLatch(
                            authMap.size());
                    for (final Map.Entry<String, Authenticator> entry : authMap
                            .entrySet()) {
                        entry.getValue().login(request,
                                new ActionListener<String[]>() {
                                    @Override
                                    public void onResponse(final String[] roles) {
                                        if (roles != null) {
                                            for (final String role : roles) {
                                                roleMap.put(role,
                                                        entry.getKey());
                                            }
                                        }
                                        latch.countDown();
                                    }

                                    @Override
                                    public void onFailure(final Throwable e) {
                                        logger.warn(
                                                "Failed to authenticate: "
                                                        + entry.getKey() + "/"
                                                        + entry.getValue(), e);
                                        latch.countDown();
                                    }
                                });
                    }
                    try {
                        latch.await();
                        authService.createToken(roleMap.keySet(),
                                new ActionListener<String>() {
                                    @Override
                                    public void onResponse(final String token) {
                                        if (logger.isDebugEnabled()) {
                                            logger.debug("Token " + token
                                                    + " is generated.");
                                        }
                                        ResponseUtil.send(request, channel,
                                                RestStatus.OK, "token", token);

                                    }

                                    @Override
                                    public void onFailure(final Throwable e) {
                                        ResponseUtil
                                                .send(request, channel,
                                                        RestStatus.BAD_REQUEST,
                                                        "message",
                                                        "Invalid username or password.");
                                    }
                                });
                    } catch (final Exception e) {
                        logger.error("Login failed.", e);
                        ResponseUtil.send(request, channel,
                                RestStatus.INTERNAL_SERVER_ERROR, "message",
                                "Login failed.");
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
