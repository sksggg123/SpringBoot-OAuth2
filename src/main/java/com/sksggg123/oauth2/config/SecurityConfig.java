package com.sksggg123.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.annotation.Resource;
import java.lang.reflect.Array;
import java.util.Arrays;

/**
 * author      : gwonbyeong-yun <sksggg123>
 * <p>
 * info        : email   - sksggg123
 * : github - github.com/sksggg123
 * : blog   - sksggg123.github.io
 * <p>
 * project     : oauth2
 * <p>
 * create date : 2019-05-03 13:19
 */

@Configuration
@EnableWebSecurity //@EnableWebSecurity 어노테이션을 명시하는 것만으로도 springSecurityFilterChain가 자동으로 포함
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource(name = "userService")
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder encoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    // ResoucreServerConfig.java에 선언된 TokenStore가 Bean으로 주입됨
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }

    @Bean
    @Override
    // ResoucreServerConfig.java에 선언된 AuthenticationManager가 Bean으로 주입됨
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(encoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .cors()
                .and()
            .csrf()
                .disable()
            .anonymous()
                .disable()
            .authorizeRequests()
                .antMatchers("/api-docs/**").permitAll()
                .and()
            .oauth2Login();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    //    @Override
//    // 스프링 시큐리티의 필터 연결을 설정하기 위한 오버라이딩이다.
//    public void configure(WebSecurity web) throws Exception {
//        web
//                .ignoring()
//                .antMatchers("/")
//
//        ;
//    }

//    @Override
//    //  인터셉터로 요청을 안전하게 보호하는 방법을 설정하기 위한 오버라이딩이다.
//    protected void configure(HttpSecurity http) throws Exception {
//
//        http.authorizeRequests()
//                .antMatchers("/**").permitAll()
//                .antMatchers("/").access("ROLE_USER")
//                .antMatchers("/").access("ROLE_ADMIN")
//            .and()
//                .oauth2Login()
//            .and()
//                .cors()
//            .and()
//                .httpBasic()
//            .and()
//                .logout().logoutSuccessUrl("/").permitAll()
//            .and()
//                .csrf().disable();
////        http.antMatcher("/**")
////                .authorizeRequests()
////                .antMatchers("/", "/h2-console/**", "/favicon.ico", "/login**").permitAll() // "/login**" 옵션 추가
////                .antMatchers("/", "/h2-console/**", "/favicon.ico", "/login**").access("ROLE_USER")
////                .antMatchers("/", "/h2-console/**", "/favicon.ico", "/login**").access("ROLE_ADMIN")
////                .anyRequest().authenticated()
////                .and().logout().logoutSuccessUrl("/").permitAll()
////                .and().headers().frameOptions().sameOrigin()
////                .and().csrf().disable();
//        ;
//    }


}
