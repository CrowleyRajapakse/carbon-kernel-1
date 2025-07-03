/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.ui.filters;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This filter restricts URIs to be invoked with certain HTTP Methods.
 *
 * URIs and restricted methods can be configured via init-params for the filter.
 * If a service URI is restricted access with the HTTP Method in the received request,
 * this filter will return a 405 error response.
 */
public class URIMethodBlockFilter implements Filter {
    private static Log log = LogFactory.getLog(URIMethodBlockFilter.class);
    private Map<Pattern, Set<String>> blockedURIsAndMethods = new HashMap<>();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Enumeration<String> paramNames = filterConfig.getInitParameterNames();

        while (paramNames.hasMoreElements()) {
            String uri = paramNames.nextElement();
            String methods = filterConfig.getInitParameter(uri);

            Set<String> methodSet = Arrays.stream(methods.split(",")).map(String::trim).map(String::toUpperCase)
                    .collect(Collectors.toSet());

            String uriRegex = uri.replace("*", ".*");
            Pattern uriPattern = Pattern.compile(uriRegex);

            blockedURIsAndMethods.put(uriPattern, methodSet);
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResp = (HttpServletResponse) servletResponse;

        String method = httpReq.getMethod().toUpperCase();
        String requestURI = httpReq.getRequestURI();

        Set<String> restrictedMethodsForRequestedURI = getRestrictedMethodsForURI(requestURI);
        if (!restrictedMethodsForRequestedURI.isEmpty() && restrictedMethodsForRequestedURI.contains(method)) {
            if (log.isDebugEnabled()) {
                log.debug(method + " Request to " + requestURI + " was blocked as the method is not allowed");
            }
            httpResp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, method + " method is not allowed for " +
                    "this operation");
            return; // Don't continue the chain
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
    }

    /**
     * This method will check whether the requestedURI matches any of the URIs configured,
     * if a match is found this will return the set of restricted http methods for that URI
     *
     * @param requestedURI  requested URI
     * @return    Set of restricted HTTP methods, if no match is found this will return an empty set.
     */
    private Set<String> getRestrictedMethodsForURI(String requestedURI) {
        Set<String> methods = new HashSet<>();
        for (Map.Entry<Pattern, Set<String>> entry : blockedURIsAndMethods.entrySet()) {
            Pattern uriPattern = entry.getKey();
            if (uriPattern.matcher(requestedURI).matches()) {
                methods = entry.getValue();
            }
        }
        return methods;
    }

}
