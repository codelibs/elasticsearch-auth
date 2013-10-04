package org.codelibs.elasticsearch.auth.util;

import java.io.IOException;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.XContentRestResponse;
import org.elasticsearch.rest.XContentThrowableRestResponse;
import org.elasticsearch.rest.action.support.RestXContentBuilder;

public class ResponseUtil {
    private static final ESLogger logger = Loggers
            .getLogger(ResponseUtil.class);;

    private ResponseUtil() {
    }

    public static void send(final RestRequest request,
            final RestChannel channel, final RestStatus status,
            final String... args) {
        try {
            final XContentBuilder builder = RestXContentBuilder
                    .restContentBuilder(request);
            builder.startObject();
            builder.field("status", status.getStatus());
            for (int i = 0; i < args.length; i += 2) {
                builder.field(args[i], args[i + 1]);
            }
            builder.endObject();
            channel.sendResponse(new XContentRestResponse(request, status,
                    builder));
        } catch (final IOException e) {
            logger.error("Failed to send a response.", e);
            try {
                channel.sendResponse(new XContentThrowableRestResponse(request,
                        e));
            } catch (final IOException e1) {
                logger.error("Failed to send a failure response.", e1);
            }
        }
    }
}
