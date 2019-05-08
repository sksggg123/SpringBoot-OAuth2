package com.sksggg123.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.filter.CompositeFilter;

import javax.annotation.Resource;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Filter;

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
//@EnableWebSecurity //@EnableWebSecurity 어노테이션을 명시하는 것만으로도 springSecurityFilterChain가 자동으로 포함
//@EnableOAuth2Sso
@EnableOAuth2Client
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    OAuth2ClientContext oauth2ClientContext;

//    @Resource(name = "userService")
//    private UserDetailsService userDetailsService;
//
//    @Bean
//    public PasswordEncoder encoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }
//
//    @Bean
//    // ResoucreServerConfig.java에 선언된 TokenStore가 Bean으로 주입됨
//    public TokenStore tokenStore() {
//        return new InMemoryTokenStore();
//    }
//
//    @Bean
//    @Override
//    // ResoucreServerConfig.java에 선언된 AuthenticationManager가 Bean으로 주입됨
//    protected AuthenticationManager authenticationManager() throws Exception {
//        return super.authenticationManager();
//    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService)
//                .passwordEncoder(encoder());
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//            .cors()
//                .and()
//            .csrf()
//                .disable()
//            .anonymous()
//                .disable()
//            .authorizeRequests()
//                .antMatchers("/api-docs/**").permitAll()
//                .and()
//            .authorizeRequests()
//                .antMatchers("/**").permitAll()
//                .antMatchers("/").access("ROLE_USER")
//                .antMatchers("/").access("ROLE_ADMIN")
//                .and()
//                    .oauth2Login()
//            ;
//    }
//
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(Arrays.asList("*"));
//        configuration.setAllowedMethods(Arrays.asList("*"));
//        configuration.setAllowedHeaders(Arrays.asList("*"));
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }

    //    @Override
//    // 스프링 시큐리티의 필터 연결을 설정하기 위한 오버라이딩이다.
//    public void configure(WebSecurity web) throws Exception {
//        web
//                .ignoring()
//                .antMatchers("/")
//
//        ;
//    }

    CharacterEncodingFilter filter = new CharacterEncodingFilter();

    private Filter ssoFilter() {

        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(github(), "/login/github"));
        return filters.get(0);
    }

    private Filter ssoFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
        filter.setRestTemplate(template);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId());
        tokenServices.setRestTemplate(template);
        filter.setTokenServices(tokenServices);
        return (Filter) filter;
    }

    @Bean
    @ConfigurationProperties("github.resource")
    public ResourceServerProperties githubResource() {
        return new ResourceServerProperties();
    }

    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() {
        return new ClientResources();
    }

    @Bean
    public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    @Override
    //  인터셉터로 요청을 안전하게 보호하는 방법을 설정하기 위한 오버라이딩이다.
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/", "/login**", "/webjars/**", "/error**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and().logout().logoutSuccessUrl("/").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().addFilterBefore((javax.servlet.Filter) ssoFilter(), BasicAuthenticationFilter.class)
        ;

//        http
//            .csrf()
//                .disable()
//            .antMatcher("/**")
//            .authorizeRequests()
//                .antMatchers("/**").permitAll()
//            .anyRequest()
//                .authenticated()


//
//        http
//            .authorizeRequests()
//            .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
//            .antMatchers("/", "/h2-console/**", "/api/post/list/**", "/api/rank"
//                    , "/api/post/tags", "/api/post/{\\d+}/comment/list", "/favicon.ico", "/oauth2/**", "/login/**", "/css/**"
//                    , "/images/**", "/js/**", "/console/**").permitAll()
//            .anyRequest().authenticated() //설정한 이외의 요청은 인증된 사용자만
//            .and()
//            .cors()
//            .and()
//            .oauth2Login()
//            .defaultSuccessUrl("/login/loginSuccess")
//            .failureUrl("/login/loginFailure")
//            .and()
//            .headers().frameOptions().disable()
//            .and()
//            .exceptionHandling()
//            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
//            .and()
//            .formLogin()
//            .successForwardUrl("/")
//            .and()
//            .logout()
//            .logoutUrl("/logout")
//            .logoutSuccessUrl("/")
//            .deleteCookies("JSESSIONID")
//            .invalidateHttpSession(true)
//            .and()
//            .addFilterBefore(filter, CsrfFilter.class) //문자 인코딩 필터보다 CsrfFilter를 먼저 등록한다.
//            .csrf().disable(); //크로스사이트 요청 위조




//        http.authorizeRequests()
//                .antMatchers("/**").permitAll()
//                .antMatchers("/").access("ROLE_USER")
//                .antMatchers("/").access("ROLE_ADMIN")
//            .and()
//                .oauth2Login()
//                .defaultSuccessUrl("/login/successLogin")
//                .failureUrl("/login/failLogin")
//            .and()
//                .cors()
//            .and()
//                .httpBasic()
//            .and()
//                .logout().logoutSuccessUrl("/").permitAll()
//            .and()
//                .csrf().disable();
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

class ClientResources {

    @NestedConfigurationProperty
    private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();

    public AuthorizationCodeResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }
}