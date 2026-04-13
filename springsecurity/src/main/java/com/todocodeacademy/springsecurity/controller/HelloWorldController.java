package com.todocodeacademy.springsecurity.controller;

import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@AllArgsConstructor
@PreAuthorize("denyAll()")
public class HelloWorldController {

    @GetMapping("/holasec")
    //@PreAuthoriza("hasAuthority('READ')")
    @PreAuthorize("hasRole('ADMIN')")
    public String secHelloWorld() {
        return "Con seguridad";
    }

    @GetMapping("/holanosec")
    @PreAuthorize("permitAll()")
    public String noSecHelloWorld() {
        return "Sin seguridad";
    }
}
