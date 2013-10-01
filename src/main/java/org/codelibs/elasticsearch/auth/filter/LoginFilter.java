package org.codelibs.elasticsearch.auth.filter;

import static org.elasticsearch.rest.RestStatus.OK;

import java.util.Map;

import org.codelibs.elasticsearch.auth.security.Authenticator;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.StringRestResponse;

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
                    final StringBuilder contentBuf = new StringBuilder(255);
                    for (final Map.Entry<String, Authenticator> entry : authenticatorMap
                            .entrySet()) {
                        final String loginContent = entry.getValue().login(
                                request);
                        if (loginContent != null) {
                            if (contentBuf.length() > 0) {
                                contentBuf.append('{');
                            } else {
                                contentBuf.append(',');
                            }
                            contentBuf.append('"').append(entry.getKey())
                                    .append("\":").append(loginContent);
                        }
                    }
                    contentBuf.append('}');
                    channel.sendResponse(new StringRestResponse(OK, contentBuf
                            .toString()));
                    return;
                }
            }
        }
        filterChain.continueProcessing(request, channel);
    }

}
