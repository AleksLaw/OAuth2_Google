package main.security;

import main.config.CustomUserDetailsService;
import main.model.Role;
import main.model.User;
import main.repository.UserRepo;
import main.service.ServiceUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.lang.invoke.SerializedLambda;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableOAuth2Sso
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private CustomUserDetailsService userDetailsService;
//    @Autowired
//    private ServiceUser serviceUser;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                    .authorizeRequests()
//                    .antMatchers( "/newAdmin").permitAll()
                  //  .antMatchers("/admin/**").hasAuthority("ADMIN")
                    .antMatchers("/admin/**").authenticated()
                   // .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/user/**").hasAuthority("USER")
                    .anyRequest()
                    .authenticated()
                .and()
                    .formLogin()
                    .loginPage("/login")
                    .permitAll()
                .and()
                    .logout()
                    .logoutSuccessUrl("/login")
                    .permitAll();
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        PasswordEncoder encoder = new BCryptPasswordEncoder(8);
        return encoder;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

@Bean
    public PrincipalExtractor principalExtractor(UserRepo userRepo) {
        return map -> {
        //    User user = userRepo.findById(Long.parseLong((String) map.get("sub"))).orElseGet(() -> {
            User user = userRepo.findByName((String) map.get("email"));
            if (user==null) {
                User newUser = new User();
                //  newUser.setId(Long.parseLong((String) map.get("sub")));
                newUser.setName((String) map.get("name"));
                newUser.setLastName((String) map.get("name"));
                newUser.setEmail((String) map.get("email"));
                newUser.setPassword("1");
                newUser.setLastName("lastName");
                newUser.setAge(1);
                newUser.setUserRoles(new HashSet<Role>(Collections.singleton(Role.ADMIN)));
                return userRepo.save(newUser);
            }
            return userRepo.save(user);
        };
}}

