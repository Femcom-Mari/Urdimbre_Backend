package com.urdimbre.urdimbre.service.auth;

import com.urdimbre.urdimbre.dto.auth.AuthRequestDTO;
import com.urdimbre.urdimbre.dto.auth.AuthResponseDTO;
import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthService {

    UserResponseDTO register(UserRegisterDTO dto);

    AuthResponseDTO login(AuthRequestDTO dto);

    void logout(HttpServletRequest request, HttpServletResponse response);

    AuthResponseDTO refreshToken(String refreshToken);
}