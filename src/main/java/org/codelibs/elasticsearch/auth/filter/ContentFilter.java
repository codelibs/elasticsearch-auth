package org.codelibs.elasticsearch.auth.filter;

import org.codelibs.elasticsearch.auth.security.LoginConstraint;
import org.codelibs.elasticsearch.auth.service.AuthService;
import org.codelibs.elasticsearch.auth.util.ResponseUtil;
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

    public ContentFilter(final AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        if (constraints == null) {
            try {
                authService.reload();
            } catch (final Exception e) {
                logger.warn("Failed to reload AuthService.", e);
            }
            if (constraints == null) {
                ResponseUtil.send(request, channel,
                        RestStatus.SERVICE_UNAVAILABLE, "message",
                        "A service is not available.");
                return;
            }
        }

        final String rawPath = request.rawPath();
        for (final LoginConstraint constraint : constraints) {
            if (constraint.match(rawPath)) {
                if (logger.isDebugEnabled()) {
                    logger.debug(rawPath + " is filtered.");
                }
                if (authService.authenticate(authService.getToken(request),
                        constraint.getRoles(request.method()))) {
                    // ok
                    break;
                } else {
                    // invalid
                    ResponseUtil.send(request, channel, RestStatus.FORBIDDEN,
                            "message", "Forbidden. Not authorized.");
                    return;
                }
            }
        }
        filterChain.continueProcessing(request, channel);
    }

    public void setLoginConstraints(final LoginConstraint[] constraints) {
        this.constraints = constraints;
    }

}
