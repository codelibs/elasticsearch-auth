package org.codelibs.elasticsearch.auth.util;

import java.io.IOException;

import org.codelibs.elasticsearch.auth.AuthException;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public class ResponseUtil {
    private static final ESLogger logger = Loggers
            .getLogger(ResponseUtil.class);;

    private ResponseUtil() {
    }

    public static void send(final RestRequest request,
            final RestChannel channel, final AuthException e) {
        send(request, channel, e.getStatus(), "message", e.getMessage());
    }

    public static void send(final RestRequest request,
            final RestChannel channel, final RestStatus status,
            final String... args) {
        try {
            final XContentBuilder builder = JsonXContent.contentBuilder();
            builder.startObject();
            builder.field("status", status.getStatus());
            for (int i = 0; i < args.length; i += 2) {
                builder.field(args[i], args[i + 1]);
            }
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (final IOException e) {
            logger.error("Failed to send a response.", e);
            try {
                channel.sendResponse(new BytesRestResponse(channel, e));
            } catch (final IOException e1) {
                logger.error("Failed to send a failure response.", e1);
            }
        }
    }
}
