package com.springsecurityjwt.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DashboardController {

	@GetMapping(value = {"/","/home"})
	public String home() {
		return "Welcome to Spring Security";
	}
}
