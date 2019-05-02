package com.sksggg123.oauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @RequestMapping("/test")
    public String testController() {
        return "Test Page";
    }
}
