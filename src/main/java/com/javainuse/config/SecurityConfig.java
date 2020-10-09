package com.javainuse.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// authentication
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("javainuse")
				.password("{noop}javainuse").roles("USER");
	}

	// authorization
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/**").authorizeRequests().anyRequest().hasRole("USER")
				.and().formLogin().loginPage("/login.jsp")
				.failureUrl("/login.jsp?error=1").loginProcessingUrl("/login")
				.permitAll().and().logout()
				.logoutSuccessUrl("/listEmployees.html");

	}

}

/*
Error : There is no PasswordEncoder mapped for the id “null”
Solution : https://www.yawintutor.com/illegalargumentexception-there-is-no-passwordencoder-mapped-for-the-id-null/

Solution 1
The default PasswordEncoder is NoOpPasswordEncoder, which deals for plain text passwords until Spring Security 5.0. The default in Spring Security 5 is changed to DelegatingPasswordEncoder that required Password Storage Format.

The password storage format is {encrypt}password. Add {noop}, before the password. {noop} informs that password is a plain text, no encryption is used.

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("user").password("{noop}password").roles("USER")
			.and()
			.withUser("admin").password("{noop}password").roles("ADMIN");
	}
Solution 2
In the Password Encoder, set the default PasswordEncoder NoOpPasswordEncoder. The example below shows the default Password Encoder with NoOpPasswordEncoder.

The NoOpPasswordEncoder class is deprecated. This solution should not be used in production environment

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.passwordEncoder(NoOpPasswordEncoder.getInstance())
			.withUser("user").password("password").roles("USER")
			.and()
			.withUser("admin").password("password").roles("ADMIN");
	}
 */