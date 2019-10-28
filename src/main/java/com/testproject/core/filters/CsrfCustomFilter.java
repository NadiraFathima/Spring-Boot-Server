package com.testproject.core.filters;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

//OncePerRequestFilter provides one single execution of the filter per request
public class CsrfCustomFilter extends OncePerRequestFilter {

    private final static String CSRF_TOKEN = "CSRF_TOKEN";
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if(Objects.nonNull(csrfToken)){
            Cookie cookie = WebUtils.getCookie(request, CSRF_TOKEN);
            if(cookie==null) {
                cookie = new Cookie(CSRF_TOKEN, csrfToken.getToken());
                //The cookie is visible in the server to all the pages in the directory specified, and all the pages in that directory's subdirectories.
                cookie.setPath("/");
                response.addCookie(cookie);
            }
        }
        //propogates request and response to next filter in line
        filterChain.doFilter(request, response);
    }

}
