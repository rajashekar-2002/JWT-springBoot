package com.security.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.security.security.service.MyUserDetailsService;

import jakarta.servlet.Filter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  //define custom userDetailsService
  @Autowired
  private MyUserDetailsService userDetailsService;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
  }


  @Bean
  public JwtFilter jwtFilter;

  // cerate own custom authprovider
  //must define a passwordencoder
  //encode password before saving to database
  public AuthenticationProvider authProvider(PasswordEncoder passwordEncoder) {
    //we need a authenticator that uses database
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    // setuserdetailsservice takes care to connect to user table
    //takes UserDetailsService as input
    //it is an interface defaine a class
    provider.setUserDetailsService(userDetailsService);
    provider.setPasswordEncoder(passwordEncoder);
    // DaoAuthenticationProvider implements DaoAuthenticationProvider
    return provider;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http)
    throws Exception {
    http
      //disable csrf
      //becaz use stateless restfulapi
      .csrf(customizer -> customizer.disable())
      .authorizeHttpRequests(request ->
        request
          //permit these path for all user
          .requestMatchers("/all","/token")
          .permitAll()
          //authenticate for all paths
          .anyRequest()
          .authenticated()
      )
      //default form settings
      //form login
      // .formLogin(Customizer.withDefaults())
      //below formlogin is not required for simple form login
      //cerate a  custoum login form
      .formLogin(formLogin ->
        formLogin
          .loginPage("/login")
        .loginProcessingUrl("/login")
          .defaultSuccessUrl("/all", true)
          .permitAll()
      //   // .failureUrl("login?error=true")
      )
      //this will add all basic http request for auth including popup login
      // .httpBasic(Customizer.withDefaults())
      .sessionManagement(session ->
        //use stateless restfullapi
        //new  sessionid for all new request
        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        
      )
      //add jwt filter before userpassword auth filter
      .addFilterBefore(jwtFilter,(Class<? extends Filter>) UsernamePasswordAuthenticationToken.class);

    return http.build();
  }


  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
    return config.getAuthenticationManager();
  }
}




