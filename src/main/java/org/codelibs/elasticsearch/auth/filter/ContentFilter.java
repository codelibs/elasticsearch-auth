package org.codelibs.elasticsearch.auth.filter;

import java.util.concurrent.atomic.AtomicBoolean;

import org.codelibs.elasticsearch.auth.security.LoginConstraint;
import org.codelibs.elasticsearch.auth.service.AuthService;
import org.codelibs.elasticsearch.auth.util.ResponseUtil;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public class ContentFilter extends RestFilter {
    private static final ESLogger logger = Loggers
            .getLogger(ContentFilter.class);

    private volatile LoginConstraint[] constraints = null;

    private AuthService authService;

    private AtomicBoolean initializing = new AtomicBoolean(false);

    public ContentFilter(final AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        if (constraints == null) {
            init(request, channel, filterChain);
        } else {
            processNext(request, channel, filterChain);
        }
    }

    protected void init(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        if (logger.isDebugEnabled()) {
            logger.debug("initializing: {0}", initializing);
        }
        if (!initializing.getAndSet(true)) {
            authService.init(new ActionListener<Void>() {
                @Override
                public void onResponse(final Void response) {
                    initializing.set(false);
                    if (constraints == null) {
                        sendServiceUnavailable(request, channel);
                    } else {
                        processNext(request, channel, filterChain);
                    }
                }

                @Override
                public void onFailure(final Throwable e) {
                    initializing.set(false);
                    logger.warn("Failed to reload AuthService.", e);
                    sendServiceUnavailable(request, channel);
                }
            });
        } else {
            sendServiceUnavailable(request, channel);
        }
    }

    protected void processNext(final RestRequest request,
            final RestChannel channel, final RestFilterChain filterChain) {
        final String rawPath = request.rawPath();
        for (final LoginConstraint constraint : constraints) {
            if (constraint.match(rawPath)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("{} is filtered.", rawPath);
                }

                final String token = authService.getToken(request);
                authService.authenticate(token,
                        constraint.getRoles(request.method()),
                        new ActionListener<Boolean>() {

                            @Override
                            public void onResponse(final Boolean isAuthenticated) {
                                if (isAuthenticated) {
                                    filterChain.continueProcessing(request,
                                            channel);
                                } else {
                                    // invalid
                                    ResponseUtil.send(request, channel,
                                            RestStatus.FORBIDDEN, "message",
                                            "Forbidden. Not authorized.");
                                }
                            }

                            @Override
                            public void onFailure(final Throwable e) {
                                logger.error("Authentication failed: token: "
                                        + token, e);
                                ResponseUtil.send(request, channel,
                                        RestStatus.FORBIDDEN, "message",
                                        "Forbidden. Authentication failed.");
                            }
                        });
                return;
            }
        }
        filterChain.continueProcessing(request, channel);
    }

    protected void sendServiceUnavailable(final RestRequest request,
            final RestChannel channel) {
        ResponseUtil.send(request, channel, RestStatus.SERVICE_UNAVAILABLE,
                "message", "A service is not available.");
        return;
    }

    public void setLoginConstraints(final LoginConstraint[] constraints) {
        this.constraints = constraints;
    }

}
