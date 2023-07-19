package com.example.demo.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */
@Slf4j
public class CustomerAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
            filterChain.doFilter(request, response);
        } else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    String token = authorizationHeader.substring("Bearer ".length());
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = verifier.verify(token);

                    String username = decodedJWT.getSubject();

                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

                    stream(roles).forEach(role -> {

                        authorities.add(new SimpleGrantedAuthority(role));

                    });

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    /*
                     * SecurityContextHolder: This is a class provided by Spring Security that serves as a central holder
                     * for the security-related context information in the application. It manages the security context,
                     * which includes the current user's authentication information.
                     *
                     * getContext(): This static method is called on the SecurityContextHolder class to obtain the
                     * current security context associated with the current thread. The security context holds the
                     * authentication details for the user accessing the application.
                     *
                     * setAuthentication(authenticationToken): This method is used to set the authentication information
                     * for the current user in the security context
                     *
                     * When `setAuthentication(authenticationToken)` is called, it establishes the user's authentication,
                     * allowing access to protected resources. This is commonly used in custom authentication mechanisms
                     * to handle successful login, such as validating credentials or token-based authentication. Proper
                     * authentication is crucial for securing sensitive resources, and clearing authentication on logout
                     * or session expiration ensures security integrity.
                     * */

                    filterChain.doFilter(request, response);
                } catch (Exception exception) {
                    log.error("Error logging in:{}", exception.getMessage());
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message", exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                filterChain.doFilter(request, response);
                /*
                 * filterChain: This is an instance of the FilterChain interface, which represents the chain of filters
                 * that will be applied to the incoming HTTP request before reaching the servlet or endpoint responsible
                 * for processing the request.
                 *
                 * doFilter(request, response): This method is called on the filterChain to continue the execution of the
                 * filter chain. It passes the request and response objects to the next filter in the chain. If there are
                 * no more filters in the chain, the request will eventually reach the servlet or endpoint for further
                 * processing.
                 *
                 * `filterChain.doFilter(request, response)` allows the current filter to complete its tasks and pass
                 * control to the next filter in the chain. This continues until all filters have executed, enabling
                 * various tasks like authentication, authorization, logging, and more. In security, custom filters can
                 * determine user authentication and access permissions before continuing the chain or denying access.
                 * The method ensures that the request undergoes all filter tasks before reaching the final servlet or
                 * endpoint for handling.
                 * */
            }
        }
    }
}

