package com.example.securitydemo;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity          // Tells Spring that this is a web security configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("solomon")
                .password("grundy69")
                .roles("ADMIN")
                .and()
                .withUser("paul")
                .password("aniks69")
                .roles("USER");
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {       // Final method for authentication. setting up as password encoder. Do not use the nooppassworencoder
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {          //Httpsecurity lets yuo configure the paths and set the access restrictions for those paths
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")      // Can pass in list of roles that have access.
                .antMatchers("/").permitAll()       //Tells spring to permit this API to all users
                .and().formLogin();         // default configuration of spring, specifies the type of login for spring to use

//              .antMatchers("/**")     //specifies API's using wildcards. States that all APIs can be accessed
    }
}

