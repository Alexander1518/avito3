package com.amr.project.webapp.config.security;


import com.amr.project.webapp.config.security.handler.PassEncoder;
import com.amr.project.webapp.config.security.service.CustomAuthenticationProvider;
import com.amr.project.webapp.config.security.service.CustomWebAuthenticationDetailsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;



@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final CustomWebAuthenticationDetailsSource authenticationDetailsSource;
    private final PassEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService, CustomWebAuthenticationDetailsSource authenticationDetailsSource, PassEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.passwordEncoder = passwordEncoder;
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
                .antMatchers("/login","/logout").permitAll()
                .antMatchers("/**").permitAll()
                .antMatchers("/swagger/","/v3/").permitAll()
                .antMatchers("/swagger/*").permitAll()
                .and().formLogin()
                .authenticationDetailsSource(authenticationDetailsSource)
                .loginPage("/login")
                .loginPage("/login1FAQR")
                .and().logout().logoutUrl("/logout")
                .logoutSuccessUrl("/login1FA");
    }


    @Bean
    public DaoAuthenticationProvider authProvider() {
        CustomAuthenticationProvider authProvider = new CustomAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder.passwordEncoder());
        return authProvider;
    }

}