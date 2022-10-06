package com.spring.app.config;

import com.spring.app.service.UserDetailsServiceImpl;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SuppressWarnings("deprecation")
@EnableWebSecurity
@Configuration
@Order(1)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	 @Bean
	    public UserDetailsService userDetailsService() {
	        return new UserDetailsServiceImpl();
	    }
	     
	    @Bean
	    public BCryptPasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }
	     
	    @Bean
	    public DaoAuthenticationProvider authenticationProvider() {
	        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	        authProvider.setUserDetailsService(userDetailsService());
	        authProvider.setPasswordEncoder(passwordEncoder());
	         
	        return authProvider;
	    }
	 
   @Override
   protected void configure(HttpSecurity http) throws Exception {

      http.csrf().disable();

      // Requires login with role ROLE_EMPLOYEE or ROLE_MANAGER.
      // If not, it will redirect to /admin/login.
      http.authorizeRequests().antMatchers("/admin/orderList", "/admin/order", "/admin/accountInfo")//
            .access("hasAnyRole('ROLE_EMPLOYEE', 'ROLE_MANAGER')");

      // Pages only for MANAGER
      http.authorizeRequests().antMatchers("/admin/product").access("hasRole('ROLE_MANAGER')");

      // When user login, role XX.
      // But access to the page requires the YY role,
      // An AccessDeniedException will be thrown.
      http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/403");

      // Configuration for Login Form.
      http.authorizeRequests().and().formLogin()//

            //
            .loginProcessingUrl("/j_spring_security_check") // Submit URL
            .loginPage("/admin/login")//
            .defaultSuccessUrl("/admin/accountInfo")//
            .failureUrl("/admin/login?error=true")//
            .usernameParameter("userName")//
            .passwordParameter("password")

            // Configuration for the Logout page.
            // (After logout, go to home page)
            .and().logout().logoutUrl("/admin/logout").logoutSuccessUrl("/");

   }
}