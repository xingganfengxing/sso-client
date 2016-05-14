package com.pcitc.sso.client;

import com.pcitc.sso.client.utils.FilterConstants;
import com.pcitc.sso.common.user.User;
import com.pcitc.sso.common.utils.SSOException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by longjiazuo on 2015/5/13.
 */
public class SSOFilter implements Filter {

    private List<Pattern> exclusions = new ArrayList<Pattern>();
    private String logoutUri;

    public void init(FilterConfig filterConfig) throws ServletException {
        String serverHost = filterConfig.getInitParameter(FilterConstants.ConfigParam.SERVER_HOST);
        if (serverHost == null) {
            throw new ServletException("Missing init parameter " + FilterConstants.ConfigParam.SERVER_HOST);
        }
        SSOClient.setServerHost(serverHost);

        String loginBack = filterConfig.getInitParameter(FilterConstants.ConfigParam.LOGIN_BACK);
        if (loginBack == null) {
            throw new ServletException("Missing init parameter " + FilterConstants.ConfigParam.LOGIN_BACK);
        }
        SSOClient.setBackUrl(loginBack);

        String appKey = filterConfig.getInitParameter(FilterConstants.ConfigParam.APP_KEY);
        if (appKey == null) {
            throw new ServletException("Missing init parameter " + FilterConstants.ConfigParam.APP_KEY);
        }
        SSOClient.setAppKey(appKey);

        String appSecret = filterConfig.getInitParameter(FilterConstants.ConfigParam.APP_SECRET);
        if (appSecret == null) {
            throw new ServletException("Missing init parameter " + FilterConstants.ConfigParam.APP_SECRET);
        }
        SSOClient.setAppSecret(appSecret);

        logoutUri = filterConfig.getInitParameter(FilterConstants.ConfigParam.LOGOUT_URI);

        String exclusionStr = filterConfig.getInitParameter(FilterConstants.ConfigParam.EXCLUSIONS);
        if (exclusionStr != null && !exclusionStr.isEmpty()) {
            String[] inputs = exclusionStr.split(FilterConstants.SEPARATOR);
            for (String input : inputs) {
                Pattern pattern = regexCompile(input.trim());
                if (pattern != null) {
                    exclusions.add(pattern);
                }
            }
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String reqUri = httpRequest.getRequestURI();
        if (isExcluded(reqUri)) {
            chain.doFilter(request, response);
            return;
        }

        if (reqUri.equalsIgnoreCase(logoutUri)) {
            SSOClient.doLogout(httpRequest, httpResponse);
        }
        else {
            User user = null;
            try {
                user = SSOClient.getLoginUser(httpRequest, httpResponse);
            } catch (SSOException e) {
            }
            if (user == null) {
                SSOClient.doLogin(httpRequest, httpResponse);
            }
        }

        if (!httpResponse.isCommitted()) {
            chain.doFilter(request, response);
        }
    }

    public void destroy() {

    }

    private Pattern regexCompile(String input) {
        if (input == null || input.isEmpty()) {
            return null;
        }
        String regex = input.replace("*", "(.*)").replace("?", "(.{1})");
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    private boolean isExcluded(String uri) {
        for (Pattern exclusion : exclusions) {
            Matcher matcher = exclusion.matcher(uri);
            if (matcher.matches()) {
                return true;
            }
        }
        return false;
    }

}
