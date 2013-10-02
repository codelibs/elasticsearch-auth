package org.codelibs.elasticsearch.auth.filter;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.elasticsearch.rest.RestStatus.OK;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.codelibs.elasticsearch.auth.security.Authenticator;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.XContentRestResponse;
import org.elasticsearch.rest.XContentThrowableRestResponse;

public class LoginFilter extends RestFilter {
    private static final ESLogger logger = Loggers.getLogger(LoginFilter.class);

    private Method[] methods;

    private String loginPath;

    private Map<String, Authenticator> authenticatorMap;

    public LoginFilter(final Map<String, Authenticator> authenticatorMap,
            final Method[] methods, final String loginPath) {
        this.authenticatorMap = authenticatorMap;
        this.methods = methods;
        this.loginPath = loginPath;
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        for (final Method method : methods) {
            if (method == request.method()) {
                final String rawPath = request.rawPath();
                if (loginPath.equals(rawPath)) {

                    final Map<String, Object> sourceMap = new HashMap<String, Object>();
                    for (final Map.Entry<String, Authenticator> entry : authenticatorMap
                            .entrySet()) {
                        final Map<String, Object> loginObj = entry.getValue()
                                .login(request);
                        if (loginObj != null) {
                            sourceMap.put(entry.getKey(), loginObj);
                        }
                    }
                    try {
                        channel.sendResponse(new XContentRestResponse(request,
                                OK, jsonBuilder().value(sourceMap)));
                    } catch (final IOException e) {
                        logger.error("Failed to send a response.", e);
                        try {
                            channel.sendResponse(new XContentThrowableRestResponse(
                                    request, e));
                        } catch (final IOException e1) {
                            logger.error("Failed to send a failure response.",
                                    e1);
                        }
                    }
                    return;
                }
            }
        }
        filterChain.continueProcessing(request, channel);
    }

}
