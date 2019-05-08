package com.sksggg123.oauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * author       : gwonbyeong-yun <sksggg123>
 * <p>
 * email        : sksggg123
 * github       : github.com/sksggg123
 * blog         : sksggg123.github.io
 * <p>
 * project      : oauth2
 * <p>
 * create date  : 2019-05-06 01:32
 */
@Controller
public class ViewController {

    @GetMapping("/")
    public String index() {

        return "index.html";
    }
}
