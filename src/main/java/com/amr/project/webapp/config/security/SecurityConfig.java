package com.amr.project.webapp.config.security;


import com.amr.project.OAuth.CustomOAuth2User;
import com.amr.project.OAuth.CustomOAuth2UserService;
import com.amr.project.service.abstracts.UserService;
import com.amr.project.service.impl.UserServiceImpl;
import com.amr.project.webapp.config.security.handler.PassEncoder;
import com.amr.project.webapp.config.security.service.CustomAuthenticationProvider;
import com.amr.project.webapp.config.security.service.CustomWebAuthenticationDetailsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final CustomWebAuthenticationDetailsSource authenticationDetailsSource;
    private final PassEncoder passwordEncoder;
    private final UserService userService;
    private final CustomOAuth2UserService oauthUserService;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService, CustomWebAuthenticationDetailsSource authenticationDetailsSource, PassEncoder passwordEncoder, UserServiceImpl userService, CustomOAuth2UserService oauthUserService) {
        this.userDetailsService = userDetailsService;
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.oauthUserService = oauthUserService;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .cors().disable()
                .authorizeRequests()
                .antMatchers("/login","/logout", "/oauth/**").permitAll()
                .antMatchers("/**").permitAll()
                .antMatchers("/swagger/","/v3/").permitAll()
                .antMatchers("/swagger/*").permitAll()
                .and().formLogin()
                .authenticationDetailsSource(authenticationDetailsSource)
                .loginPage("/login")
                .loginPage("/login1FAQR")
                .and().logout().logoutUrl("/logout")
                .logoutSuccessUrl("/login1FA");


        http.authorizeRequests()
                .antMatchers("/", "/login", "/oauth/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                .oauth2Login()
                .loginPage("/login")
                .userInfoEndpoint()
                .userService(oauthUserService);
        http.oauth2Login()
                .loginPage("/login")
                .userInfoEndpoint()
                .userService(oauthUserService)
                .and()
                .successHandler(new AuthenticationSuccessHandler() {

                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                        Authentication authentication) throws IOException, ServletException {

                        CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();

                        userService.processOAuthPostLogin(oauthUser.getEmail());

                        response.sendRedirect("/main");
                    }
                });
    }


    @Bean
    public DaoAuthenticationProvider authProvider() {
        CustomAuthenticationProvider authProvider = new CustomAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder.passwordEncoder());
        return authProvider;
    }

}