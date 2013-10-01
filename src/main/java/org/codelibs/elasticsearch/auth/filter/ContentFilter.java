package org.codelibs.elasticsearch.auth.filter;

import static org.elasticsearch.rest.RestStatus.OK;

import java.io.IOException;

import org.codelibs.elasticsearch.auth.logic.LoginLogic;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.XContentRestResponse;
import org.elasticsearch.rest.XContentThrowableRestResponse;
import org.elasticsearch.rest.action.support.RestXContentBuilder;

public class ContentFilter extends RestFilter {
    private static final ESLogger logger = Loggers
            .getLogger(ContentFilter.class);

    private LoginLogic[] loginLogics;

    public ContentFilter(final LoginLogic[] loginLogics) {
        this.loginLogics = loginLogics;
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        final String rawPath = request.rawPath();
        for (final LoginLogic loginLogic : loginLogics) {
            if (loginLogic.match(rawPath)) {
                if (loginLogic.authenticate(request)) {
                    // ok
                    break;
                } else {
                    // invalid
                    processError(request, channel);
                    return;
                }
            }
        }
        filterChain.continueProcessing(request, channel);
    }

    protected void processError(final RestRequest request,
            final RestChannel channel) {
        try {
            final XContentBuilder builder = RestXContentBuilder
                    .restContentBuilder(request);
            builder.startObject();
            builder.field("status", "error");
            builder.field("code", 403);
            builder.field("message", "Forbidden");
            builder.endObject();
            channel.sendResponse(new XContentRestResponse(request, OK, builder));
        } catch (final IOException e) {
            logger.error("Failed to send a error response.", e);
            try {
                channel.sendResponse(new XContentThrowableRestResponse(request,
                        e));
            } catch (final IOException e1) {
                logger.error("Failed to send a response.", e1);
            }
        }
    }

}
