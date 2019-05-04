package com.sksggg123.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;

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

    @Override
    // 스프링 시큐리티의 필터 연결을 설정하기 위한 오버라이딩이다.
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/")

        ;
    }

    @Override
    //  인터셉터로 요청을 안전하게 보호하는 방법을 설정하기 위한 오버라이딩이다.
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/**").permitAll()
                .antMatchers("/").access("ROLE_USER")
                .antMatchers("/").access("ROLE_ADMIN")
            .and()
                .oauth2Login()
            .and()
                .cors()
            .and()
                .httpBasic()
            .and()
                .logout().logoutSuccessUrl("/").permitAll()
            .and()
                .csrf().disable();
//        http.antMatcher("/**")
//                .authorizeRequests()
//                .antMatchers("/", "/h2-console/**", "/favicon.ico", "/login**").permitAll() // "/login**" 옵션 추가
//                .antMatchers("/", "/h2-console/**", "/favicon.ico", "/login**").access("ROLE_USER")
//                .antMatchers("/", "/h2-console/**", "/favicon.ico", "/login**").access("ROLE_ADMIN")
//                .anyRequest().authenticated()
//                .and().logout().logoutSuccessUrl("/").permitAll()
//                .and().headers().frameOptions().sameOrigin()
//                .and().csrf().disable();
        ;
    }


}
