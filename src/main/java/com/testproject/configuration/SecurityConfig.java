package com.testproject.configuration;

import com.testproject.core.filters.CsrfCustomFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse() )
                    .and()
                    .authorizeRequests()
                .antMatchers("/login").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .httpBasic();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{
        //autowired annotation calls this method with an instance of 'AuthenticationManagerBuilder' when SecurityConfig bean is created
        auth.inMemoryAuthentication()
            .withUser("admin")
            .password("root")
             .roles("USER");
    }

}