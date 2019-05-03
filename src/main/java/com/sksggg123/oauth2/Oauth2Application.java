package com.sksggg123.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
public class Oauth2Application implements WebMvcConfigurer {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2Application.class, args);
    }

}
