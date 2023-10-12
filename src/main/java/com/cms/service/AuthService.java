package com.cms.service;

import com.cms.dto.AuthResponse;
import com.cms.dto.LoginRequestDto;
import com.cms.dto.SignupRequestDto;

public interface AuthService {

	AuthResponse login(LoginRequestDto loginRequestDto);

	AuthResponse signup(SignupRequestDto signupRequestDto);

}
