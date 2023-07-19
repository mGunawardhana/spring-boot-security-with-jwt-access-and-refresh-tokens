package com.example.demo.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is:{}", username);
        log.info("Password is:{}", password);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        /*
         * UsernamePasswordAuthenticationToken: This is a class provided by Spring Security that represents an
         * authentication token for username and password-based authentication. It is a specific implementation of the
         * Authentication interface, designed to hold the credentials of a user during the authentication process.
         *
         * UsernamePasswordAuthenticationToken instance with the provided username and password, you are preparing the
         * authentication token to be passed to the authentication manager.
         */

        return authenticationManager.authenticate(authenticationToken);
        /*
         * The AuthenticationManager is responsible for handling authentication requests and validating credentials.
         *
         * authenticate(authenticationToken): This method is called on the authenticationManager to perform the
         * authentication process. The authenticate() method takes the UsernamePasswordAuthenticationToken as an
         * argument, which holds the username and password for authentication.
         *
         * The authenticate() method will attempt to authenticate the user by verifying the provided credentials against
         * the registered user details, such as username and hashed password, stored in the application's authentication
         * provider (e.g., database, LDAP, or custom authentication source). If the provided credentials match a valid
         * user's credentials, the authentication process will succeed, and an Authentication object representing the
         * authenticated user will be returned. Otherwise, if the authentication fails (e.g., due to incorrect
         * credentials or the user not being found), an exception, such as AuthenticationException, will be thrown.
         * In summary, the code snippet is a typical way to initiate the authentication process in Spring Security using
         * a UsernamePasswordAuthenticationToken. The authenticationManager will handle the authentication process and
         * return an Authentication object if successful, or throw an exception if the authentication fails
         */

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = (User) authentication.getPrincipal();
        /*
         * getPrincipal(): This method is called on the authentication object to retrieve the principal object associated
         * with the authenticated user. The principal represents the authenticated user.
         *
         * In the context of Spring Security, the getPrincipal() method is used to obtain the authenticated user details
         * after a successful authentication process. The User class typically represents the user's details, such as the
         * username, password, roles, and other relevant information.
         *
         * By retrieving the authenticated user, you can access and use the user's information for various purposes
         * within the application, such as customizing the user's experience, performing user-specific actions, or making
         * decisions based on the user's roles and permissions.
         *
         * It's important to note that the exact implementation of the User class and how the user details are populated
         * during authentication might vary based on the application's configuration and user management approach. In
         * some cases, instead of casting to User, you may use other custom user details classes or interfaces, depending
         * on the specific application requirements.
         * */

        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        /*
        * HMAC256: This is a constant defined in the Algorithm enumeration. It refers to the HMAC (Hash-based Message
        * Authentication Code) algorithm using the SHA-256 hash function. HMAC is used for message authentication and
        * ensures the integrity and authenticity of the data.
        *
        * "secret": This is the secret key used for HMAC. It is a string representing the secret key that will be used
        * in combination with the SHA-256 algorithm to create the digital signature for JWTs.
        *
        * "secret": This is the secret key used for HMAC. It is a string representing the secret key that will be used
        * in combination with the SHA-256 algorithm to create the digital signature for JWTs.
        *
        * .getBytes(): This method converts the "secret" string to a byte array. The HMAC algorithm requires the secret
        * key as bytes, so this step converts the secret string to bytes.
        *
        * When combined, Algorithm.HMAC256("secret".getBytes()) creates an instance of the HMAC256 algorithm with the
        * provided secret key. This algorithm can be used to sign and verify JWTs using the specified cryptographic
        * configuration.
        * */

        String access_token = JWT.create().withSubject(user.getUsername()).withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)).withIssuer(request.getRequestURL().toString()).withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())).sign(algorithm);

        /*
        * .withSubject(user.getUsername()): This sets the "sub" claim of the JWT. The "sub" claim represents the subject
        *  of the token, which is typically the unique identifier of the user associated with the token. In this case,
        *  it seems that user.getUsername() is used to identify the subject.
        *
        * .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)): This sets the expiration time
        *  ("exp" claim) of the JWT. It calculates the expiration time as the current time (in milliseconds) plus 10
        *  minutes (10 * 60 * 1000 milliseconds). This means the token will be valid for 10 minutes from the time it
        *  was created.
        *
        * .withIssuer(request.getRequestURL().toString()): This sets the "iss" claim of the JWT, which represents the
        *  issuer of the token. The request.getRequestURL().toString() retrieves the current request URL as a string,
        *  and this value is used as the issuer of the token.
        *
        * .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())):
        * This adds a custom claim to the JWT named "roles". It appears that user.getAuthorities() returns a collection
        * of GrantedAuthority objects representing the roles or authorities associated with the user. The code maps
        * these authorities to their authority names using map(GrantedAuthority::getAuthority) and collects them into a
        * list using Collectors.toList(). The list of role names is then set as the value of the "roles" claim.
        *
        * .sign(algorithm): This is the final step to sign the JWT. The sign() method takes an algorithm (algorithm) as
        * an argument, which is used to sign the JWT. The algorithm variable should contain the cryptographic signing
        * algorithm, such as HMAC SHA-256 or RSA.
        *
        * After executing this code, access_token will hold the JWT, which can be used for authentication and
        * authorization purposes. The generated token will contain the specified claims, including the username,
        * expiration time, issuer, and roles, and it will be signed with the chosen cryptographic algorithm, ensuring
        * its integrity and authenticity.
        * */

        String refresh_token = JWT.create().withSubject(user.getUsername()).withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)).withIssuer(request.getRequestURL().toString()).sign(algorithm);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        logger.info(tokens);

        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
        /*
        * new ObjectMapper(): This creates a new instance of the Jackson ObjectMapper class. The ObjectMapper is the
        * central class provided by Jackson's Databind module, and it is used to read and write JSON data to and from
        * Java objects.
        *
        * .writeValue(response.getOutputStream(), tokens): This method call writes the tokens object as JSON data to the
        *  output stream of the HTTP response.
        *
        * getOutputStream(): This method retrieves the output stream associated with the response. It allows you to
        * write data to the response that will be sent back to the client.
        *
        * tokens: This is the Java object that contains the data you want to convert to JSON and send as the response.
        * The ObjectMapper will serialize the tokens object into a JSON representation.
        *
        * The writeValue() method will convert the tokens object into a JSON string and write it to the response's
        * output stream. The client that initiated the HTTP request will receive the JSON data as the response.
        *
        * By using writeValue() in this manner, you can easily serialize Java objects into JSON and send them as
        * responses in web applications or APIs. This allows clients to receive structured data in a format they can
        * easily parse and process.
        * */
    }
}