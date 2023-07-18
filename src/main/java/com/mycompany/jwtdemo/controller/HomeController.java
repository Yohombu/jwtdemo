package com.mycompany.jwtdemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

//    @PreAuthorize("hasRole('ADMIN')")
//    @PreAuthorize("hasAnyRole('ADMIN', 'USER')") // both admin & User allowed
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
//    @PreAuthorize("hasAnyAuthority('DELETE_AUTHORITY', 'UPDATE_DELETE_AUTHORITY')")

    @GetMapping("/hello")
    public String aayHello(){
        return "Hello from Home Controller";
    }
}
