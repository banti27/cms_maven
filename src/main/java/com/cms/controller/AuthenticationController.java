package com.cms.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cms.dto.AuthResponse;
import com.cms.dto.LoginRequestDto;
import com.cms.dto.SignupRequestDto;
import com.cms.service.AuthService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
	
	
	private final AuthService authService;

	@PostMapping("/login")
	public AuthResponse login(@RequestBody LoginRequestDto loginRequestDto) {
		return this.authService.login(loginRequestDto);
	}

	@PostMapping("/signup")
	public AuthResponse signup(@RequestBody SignupRequestDto signupRequestDto) {
		return this.authService.signup(signupRequestDto);
	}

}
