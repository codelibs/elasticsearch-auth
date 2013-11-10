package org.codelibs.elasticsearch.auth.filter;

import org.codelibs.elasticsearch.auth.AuthException;
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

public class LogoutFilter extends RestFilter {
    private static final ESLogger logger = Loggers
            .getLogger(LogoutFilter.class);

    private Method[] methods = new Method[] { Method.POST, Method.DELETE };

    private String logoutPath = "/logout";

    private AuthService authService;

    public LogoutFilter(final AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        final String rawPath = request.rawPath();
        if (rawPath.equals(logoutPath)) {
            for (final Method method : methods) {
                if (method == request.method()) {
                    final String token = authService.getToken(request);
                    if (token != null) {
                        authService.deleteToken(token,
                                new ActionListener<Void>() {
                                    @Override
                                    public void onResponse(final Void response) {
                                        ResponseUtil.send(request, channel,
                                                RestStatus.OK);
                                    }

                                    @Override
                                    public void onFailure(final Throwable e) {
                                        logger.error(
                                                "Failed to delete the token.",
                                                e);
                                        if (e instanceof AuthException) {
                                            ResponseUtil.send(request, channel,
                                                    (AuthException) e);
                                        } else {
                                            ResponseUtil
                                                    .send(request,
                                                            channel,
                                                            RestStatus.INTERNAL_SERVER_ERROR,
                                                            "message",
                                                            "Failed to delete the token.");
                                        }
                                    }
                                });
                    } else {
                        ResponseUtil.send(request, channel,
                                RestStatus.BAD_REQUEST, "message",
                                "Invalid token.");
                    }
                    return;
                }
            }
            ResponseUtil.send(request, channel, RestStatus.BAD_REQUEST,
                    "message",
                    "Unsupported HTTP method for the logout process.");
            return;
        }
        filterChain.continueProcessing(request, channel);
    }

    public void setHttpMethods(final Method[] method) {
        methods = method;
    }

    public void setLogoutPath(final String logoutPath) {
        this.logoutPath = logoutPath;
    }

}
