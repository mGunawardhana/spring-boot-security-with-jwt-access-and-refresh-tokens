package com.example.demo.security;

import com.example.demo.filter.CustomAuthenticationFilter;
import com.example.demo.filter.CustomerAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
        /*
         * passwordEncoder(bCryptPasswordEncoder): This configures the AuthenticationManagerBuilder to use the provided
         * bCryptPasswordEncoder for encoding and verifying passwords during authentication.
         *
         * .passwordEncoder(bCryptPasswordEncoder): This configures the AuthenticationManagerBuilder to use the provided
         *  bCryptPasswordEncoder for encoding and verifying passwords during authentication.
         *
         * By setting the user details service and password encoder, you are configuring the authentication mechanism to
         * use the specified UserDetailsService to load user details and the BCryptPasswordEncoder to hash and verify
         * passwords.
         *
         * With this configuration, during the authentication process, Spring Security will use the userDetailsService to
         * retrieve the user's details (e.g., username, password, roles) based on the provided username. Then, it will
         * use the bCryptPasswordEncoder to check if the provided password matches the hashed password stored in the
         * user's details.
         *
         * Overall, this code snippet sets up the foundation for the authentication process in a Spring Security-enabled
         * application, allowing users to be authenticated based on the provided credentials securely.
         *
         * */
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");
        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(STATELESS);
        /*
         * sessionManagement(): This method is called on the http object to access the session management configuration.
         *
         * sessionCreationPolicy(STATELESS): This method sets the session creation policy to STATELESS. The STATELESS
         * session creation policy means that the application will not create or use HTTP sessions to track the user's
         * authentication state.
         *
         * It's important to note that when using STATELESS session creation policy, you need to ensure that your
         * authentication mechanism (e.g., JWT-based authentication) is properly implemented and secure to maintain the
         * integrity and confidentiality of user data. Additionally, you may need to handle other security aspects, such
         * as CSRF (Cross-Site Request Forgery) protection, differently since stateless applications do not maintain
         * server-side sessions.
         *
         *
         * */

        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();
        /*
         * antMatchers("/api/login/**", "/api/token/refresh/**"): This specifies the Ant-style pattern(s) for the URL(s)
         * to which the following authorization rule will apply.
         *
         * permitAll(): This method is used to allow unrestricted access to the specified URLs. It means that any user,
         * authenticated or not, can access the specified endpoints without any restrictions.
         *
         * In this configuration, the endpoints "/api/login/**" and "/api/token/refresh/**" are allowed for all users
         * without authentication. These endpoints are typically used for user authentication and token refresh
         * processes. Allowing unrestricted access to them is necessary to initiate the authentication process. Careful
         * configuration of `permitAll()` and other authorization rules is vital to ensure proper protection of sensitive
         * resources while allowing access to necessary public and authentication-related endpoints.
         * */

        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(POST, "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");

        http.authorizeRequests().anyRequest().authenticated();
        /*
         * authorizeRequests(): This method is called on the http object to access the authorization configuration for
         * HTTP requests.
         *
         * anyRequest(): This method specifies that the following authorization rule should apply to any request made to
         * the application, regardless of the URL or HTTP method.
         *
         * authenticated(): This method specifies that any request should be authenticated, meaning that users must be
         * logged in (authenticated) to access the resources protected by this rule.
         *
         * By using `http.authorizeRequests().anyRequest().authenticated()`, all requests to the application's endpoints
         * must be authenticated. Users need valid credentials to access any part of the application, including pages,
         * APIs, or resources. Implement an authentication mechanism like form-based or token-based authentication.
         * Spring Security provides flexible configuration options to customize security requirements for your
         * application's needs.
         *
         * */

        http.addFilter(customAuthenticationFilter);
        /*
         * addFilter(customAuthenticationFilter): This method is used to add a custom authentication filter
         * (customAuthenticationFilter) to the filter chain. The filter will be executed when processing incoming
         * requests.
         *
         * By adding your custom authentication filter, you can extend the authentication capabilities of Spring Security
         * to suit your application's specific needs. Custom authentication filters are often used to integrate with
         * external authentication providers, implement single sign-on (SSO) mechanisms, or handle complex authentication
         * scenarios that cannot be handled by the default authentication mechanisms provided by Spring Security.
         *
         *
         * */

        http.addFilterBefore(new CustomerAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
        /*
         * http: This refers to the HttpSecurity object, which is part of Spring Security's configuration DSL
         * (Domain-Specific Language). It is used to configure various security aspects of your application.
         *
         * addFilterBefore(new CustomerAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class): This method is
         * used to add a custom authorization filter (CustomerAuthorizationFilter) to the filter chain before the
         * UsernamePasswordAuthenticationFilter.
         *
         * new CustomerAuthorizationFilter(): This creates a new instance of your custom CustomerAuthorizationFilter.
         * This filter should implement the necessary logic to perform authorization checks based on the authenticated
         * user's roles or other criteria.
         *
         * UsernamePasswordAuthenticationFilter.class: This is the reference to the class of the filter before which you
         * want to add your custom filter. In this case, you are placing your custom authorization filter before the
         * UsernamePasswordAuthenticationFilter.
         *
         * By adding your custom authorization filter before the UsernamePasswordAuthenticationFilter, you can perform
         * additional authorization checks or enforce specific access control rules for certain endpoints or resources
         * based on the user's authentication and roles. Custom authorization filters are often used to implement
         * fine-grained access control or to integrate with external authorization systems to enforce more complex
         * authorization rules.
         *
         * */
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
