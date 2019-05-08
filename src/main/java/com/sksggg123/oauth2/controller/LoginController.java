package com.sksggg123.oauth2.controller;

import net.minidev.json.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.function.Supplier;
import java.util.logging.Logger;

@CrossOrigin(origins = "http://localhost:8081")
@RestController
//@RequestMapping("/login")
public class LoginController {

    @GetMapping("/github")
    public String getGithubCode(@RequestParam String code, @RequestParam String state) {

        System.out.println(code + " | " + state);
        return "redirect:/";
    }

    @RequestMapping("/user")
    public Principal user(Principal principal) {
        System.out.println(principal);
        return principal;
    }

    @GetMapping("/successLogin")
    public String doLogin() {

        System.out.println("Login Success");
        return "redirect:/";
    }

    @GetMapping("/failLogin")
    public String doFail() {

        System.out.println("Login Fail");
        return "redirect:/";
    }
}
