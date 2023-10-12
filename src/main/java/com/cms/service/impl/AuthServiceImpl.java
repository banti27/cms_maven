package com.cms.service.impl;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.cms.constants.Role;
import com.cms.dto.AuthResponse;
import com.cms.dto.LoginRequestDto;
import com.cms.dto.SignupRequestDto;
import com.cms.entity.User;
import com.cms.repository.UserRepository;
import com.cms.service.AuthService;
import com.cms.service.JwtService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
	
	private final JwtService jwtService;
	private final UserRepository userRepository;
	private final AuthenticationManager authManager;
	private final PasswordEncoder passwordEncoder;

	@Override
	public AuthResponse login(LoginRequestDto loginRequestDto) {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				loginRequestDto.getUsername(),
				loginRequestDto.getPassword()
				);
		
		this.authManager.authenticate(token);
		
		User user = this.userRepository.findByEmail(loginRequestDto.getUsername())
		.orElseThrow(() -> new UsernameNotFoundException("User not found"));
		
		
		String jwt = this.jwtService.generateToken(user);
		
		AuthResponse response = new AuthResponse();
		response.setToken(jwt);
		return response;
	}

	@Override
	public AuthResponse signup(SignupRequestDto signupRequestDto) {
		
		User user = new User();
		user.setEmail(signupRequestDto.getEmail());
		user.setPassword(this.passwordEncoder.encode(signupRequestDto.getPassword()));
		user.setRole(Role.USER);
		
		
		this.userRepository.save(user);
		
		
		String jwt = this.jwtService.generateToken(user);

		AuthResponse response = new AuthResponse();
		response.setToken(jwt);
		return response;
	}

}
