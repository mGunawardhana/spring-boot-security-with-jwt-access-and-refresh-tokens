package com.example.demo.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.domain.Role;
import com.example.demo.domain.User;
import com.example.demo.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserResource {

    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        /*
         * URI (Uniform Resource Identifier):
         * A URI is a generic term that identifies a resource, either on the
         * internet or any other system. It is a string of characters used to
         * identify a name or resource, and it provides a way to access that
         * resource. URIs have two main types: URLs and URNs (Uniform Resource Names).
         *
         * URL (Uniform Resource Locator):
         * A URL is a specific type of URI that not only identifies a resource
         * but also provides the means to locate it by describing its location
         * and how to access it. URLs include the protocol (e.g., HTTP, HTTPS),
         * domain name (e.g., www.example.com), path (e.g., /resource/123), and
         * possibly other components like query parameters and fragments
         *
         */

        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        System.out.println("my log " + uri);/* my log http://localhost:8080/api/role/save */

        /*
         *How is it used? By using ServletUriComponentsBuilder.fromCurrentContextPath(),
         *  you can easily build URLs or URIs that include the current context path.
         *  This is particularly useful in scenarios where you need to generate links
         *  dynamically within your web application. For example, when generating links
         *  for redirections, pagination, or creating hyperlinks on web pages.
         */
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String authorizationHeader = request.getHeader(AUTHORIZATION);
        log.info("authorizationHeader : " + authorizationHeader);
        /* authorizationHeader : Bearer {token printing... } */

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            /*
             *  startsWith("Bearer "): This is a method call on the authorizationHeader string.
             *  The startsWith() method is a built-in Java String method that checks whether
             *  the string starts with a specified prefix. In this case, it checks if the
             *  authorizationHeader string starts with the exact string "Bearer ".
             */
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());

                /*
                 *  substring("Bearer ".length()): This is a method call on the authorizationHeader
                 *  string. The substring() method is a built-in Java String method that extracts
                 *  a substring from a given string. In this case, we are extracting the part of the
                 *  authorizationHeader string that comes after the "Bearer " prefix.
                 *
                 * 1) "Bearer ".length() calculates the length of the string "Bearer ",
                 *  which is 7 (including the space after "Bearer").
                 *
                 * 2) substring("Bearer ".length()) extracts the substring starting from
                 *  the index 7 (after "Bearer ") to the end of the authorizationHeader
                 *  string.
                 */

                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                JWTVerifier verifier = JWT.require(algorithm).build();
                /*
                 *  The JWTVerifier is typically employed in the server-side code of applications
                 *  that receive JWTs from clients (e.g., web browsers, mobile apps) as part of the
                 *  authentication process. Its main purpose is to validate the received JWT to ensure
                 *  that it hasn't been tampered with, is properly signed, and has not expired.
                 *
                 *  1) Token Verification: The primary use of JWTVerifier is to verify the authenticity and
                 *     integrity of a received JWT. It checks the token's signature using a specified cryptographic
                 *     key or certificate to ensure that the token has not been tampered with.
                 *
                 *  2) Expiration Check: JWTs often include an expiration time (the "exp" claim) that
                 *     indicates until when the token is valid. The JWTVerifier checks the expiration time
                 *     to ensure that the token has not expired and is still within its validity period.
                 *
                 *  3) Issuer and Audience Verification: JWTs may contain an issuer ("iss" claim) and an
                 *     audience ("aud" claim) to specify the token's intended recipients and the issuer of the token.
                 *     The JWTVerifier can check these claims to ensure that the token is intended for the specific
                 *     server/application and that the issuer is trusted.
                 *
                 *  4) Custom Claim Validation: JWTs can include custom claims that hold application-specific data.
                 *     The JWTVerifier allows you to define custom claim validations to check if the token contains
                 *     the necessary claims and if their values meet your application's requirements.
                 *
                 *  5) Decoding JWT Claims: Though the primary responsibility of the JWTVerifier is to verify the
                 *     token's signature and claims, it may also provide utilities to decode and access the claims
                 *     stored in the JWT without performing full verification.
                 *
                 *  By using JWTVerifier, applications can confidently validate the JWTs they receive, ensuring that
                 *  only authentic and valid tokens are accepted, and use the claims in those tokens to make informed
                 *  decisions about the user's access and permissions within the application.
                 */

                DecodedJWT decodedJWT = verifier.verify(refresh_token);

                String username = decodedJWT.getSubject();

                User user = userService.getUser(username);
                String access_token = JWT.create().withSubject(user.getUsername()).withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)).withIssuer(request.getRequestURL().toString()).withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.joining())).sign(algorithm);

                /*
                 * JWT.create(): This creates a new instance of JWT from the com.auth0:java-jwt library, which is used
                 * to build a new JWT.
                 *
                 * .withSubject(user.getUsername()): This sets the "sub" claim of the JWT. The "sub" claim represents
                 * the subject of the token, which is typically the unique identifier of the user associated with the
                 * token. In this case, it seems that user.getUsername() is used to identify the subject.
                 *
                 * .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)): This sets the expiration time
                 * ("exp" claim) of the JWT. It calculates the expiration time as the current time (in milliseconds)
                 * plus 10 minutes (10 * 60 * 1000 milliseconds). This means the token will be valid for 10 minutes from
                 * the time it was created.
                 *
                 * .withIssuer(request.getRequestURL().toString()): This sets the "iss" claim of the JWT, which
                 * represents the issuer of the token. The request.getRequestURL().toString() retrieves the current
                 * request URL as a string, and this value is used as the issuer of the token.
                 *
                 * .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.joining())):
                 *  This adds a custom claim to the JWT named "roles". It appears that user.getRoles() returns a list
                 *  of roles associated with the user, and the code maps these roles to their names (assuming Role class
                 *  has a getName() method). The roles' names are then concatenated into a single string using
                 *  Collectors.joining(), and this string is set as the value of the "roles" claim.
                 *
                 * .sign(algorithm): This is the final step to sign the JWT. The sign() method takes an algorithm
                 * (algorithm) as an argument, which is used to sign the JWT. The algorithm variable should contain
                 * the cryptographic signing algorithm, such as HMAC SHA-256 or RSA.
                 *
                 * After executing this code, access_token will hold the JWT, which can be used for authentication and
                 * authorization purposes. The generated token will contain the specified claims and will be signed with
                 * the chosen cryptographic algorithm, ensuring its integrity and authenticity.
                 *  */

                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            } catch (Exception exception) {
                log.error("Error logging in:{}", exception.getMessage());
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                /*
                 * response.setStatus(FORBIDDEN.value()) is setting the HTTP response status code to 403 - "Forbidden".
                 *
                 * response.setStatus(FORBIDDEN.value()): This sets the HTTP status code of the response to 403. When
                 * the server sends this response back to the client, it indicates that the client's request was
                 * understood, but it is not allowed to access the requested resource. In other words, the client does
                 * not have the necessary permissions to access the specific endpoint or resource.
                 */

                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing!");
        }

    }
}

@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}