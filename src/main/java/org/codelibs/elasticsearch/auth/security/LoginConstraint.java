package org.codelibs.elasticsearch.auth.security;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.elasticsearch.rest.RestRequest.Method;

public class LoginConstraint {

    private String path;

    private Map<Method, Set<String>> methodMap = new HashMap<Method, Set<String>>();

    public void setPath(final String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public boolean match(final String rawPath) {
        return rawPath.startsWith(path);
    }

    public void addCondition(final String[] methods, final String[] roles) {
        if (methods.length == 0) {
            for (final Method method : Method.values()) {
                addRoles(method, roles);
            }
        } else {
            for (final String name : methods) {
                final Method method = getEsMethod(name);
                if (method != null) {
                    addRoles(method, roles);
                }
            }
        }
    }

    public String[] getRoles(final Method method) {
        final Set<String> roleSet = methodMap.get(method);
        if (roleSet != null) {
            return roleSet.toArray(new String[roleSet.size()]);
        }
        return new String[0];
    }

    private void addRoles(final Method method, final String[] roles) {
        synchronized (methodMap) {
            Set<String> roleSet = methodMap.get(method);
            if (roleSet == null) {
                roleSet = new HashSet<String>();
                methodMap.put(method, roleSet);
            }
            for (final String role : roles) {
                roleSet.add(role);
            }
        }
    }

    private Method getEsMethod(final String method) {
        if ("get".equalsIgnoreCase(method)) {
            return Method.GET;
        } else if ("post".equalsIgnoreCase(method)) {
            return Method.POST;
        } else if ("put".equalsIgnoreCase(method)) {
            return Method.PUT;
        } else if ("delete".equalsIgnoreCase(method)) {
            return Method.DELETE;
        } else if ("options".equalsIgnoreCase(method)) {
            return Method.OPTIONS;
        } else if ("head".equalsIgnoreCase(method)) {
            return Method.HEAD;
        }
        return null;
    }

}
