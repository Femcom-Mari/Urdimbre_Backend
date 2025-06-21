package com.urdimbre.urdimbre.unit.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import com.urdimbre.urdimbre.config.TestSecurityConfig;
import com.urdimbre.urdimbre.controller.AuthController;
import com.urdimbre.urdimbre.dto.auth.AuthRequestDTO;
import com.urdimbre.urdimbre.dto.auth.AuthResponseDTO;
import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.repository.UserRepository;
import com.urdimbre.urdimbre.security.service.RateLimitingService;
import com.urdimbre.urdimbre.security.service.RateLimitingService.RateLimitResult;
import com.urdimbre.urdimbre.service.auth.AuthService;
import com.urdimbre.urdimbre.service.invite.InviteCodeService;
import com.urdimbre.urdimbre.service.token.BlacklistedTokenService;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import jakarta.servlet.http.HttpServletRequest;

@WebMvcTest(AuthController.class)
@Import(TestSecurityConfig.class)
class AuthControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private InviteCodeService inviteCodeService;

    @MockBean
    private BlacklistedTokenService blacklistedTokenService;

    @MockBean
    private RateLimitingService rateLimitingService;

    private UserRegisterDTO dto;
    private UserResponseDTO responseDTO;

    private AuthRequestDTO loginDTO;
    private AuthResponseDTO authResponseDTO;

    @BeforeEach
    void setupBeforeEach() {
        dto = UserRegisterDTO.builder()
                .username("carla123")
                .firstName("Carla")
                .lastName("Gómez")
                .pronouns(Set.of("Ella"))
                .password("Password1@")
                .email("carla@email.com")
                .inviteCode("INVITE123")
                .build();

        responseDTO = new UserResponseDTO();
        responseDTO.setId(1L);
        responseDTO.setUsername("carla123");
        responseDTO.setEmail("carla@email.com");
        responseDTO.setFullName("Carla Test");
        responseDTO.setPronouns(Set.of("Ella"));
        responseDTO.setStatus("ACTIVE");
        responseDTO.setCreatedAt("2025-06-18T12:00:00Z");
        responseDTO.setRoles(List.of("USER"));

        loginDTO = new AuthRequestDTO();
        loginDTO.setUsername("carla123");
        loginDTO.setPassword("Password1@");

        authResponseDTO = new AuthResponseDTO();
        authResponseDTO.setAccessToken("secretToken");
        authResponseDTO.setRefreshToken("secretToken");
        authResponseDTO.setUsername("carla123");
        authResponseDTO.setEmail("carla@email.com");
        authResponseDTO.setFullName("Carla Test");
    }

    @Test
    void testRegister_success() throws Exception {

        RateLimitingService.RateLimitResult rateLimitResult = new RateLimitingService.RateLimitResult(true, 10, 10);

        when(rateLimitingService.checkRegisterByIp(any(HttpServletRequest.class))).thenReturn(rateLimitResult);
        when(inviteCodeService.validateInviteCode("INVITE123")).thenReturn(true);
        when(authService.register(any(UserRegisterDTO.class))).thenReturn(responseDTO);

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("carla123"))
                .andExpect(jsonPath("$.email").value("carla@email.com"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void testRegister_invitationCode_shouldReturnBadRequest() throws Exception {

        RateLimitingService.RateLimitResult rateLimitResult = new RateLimitingService.RateLimitResult(true, 10, 10);

        when(rateLimitingService.checkRegisterByIp(any(HttpServletRequest.class))).thenReturn(rateLimitResult);
        when(inviteCodeService.validateInviteCode("INVITE123")).thenReturn(false);
        when(authService.register(any(UserRegisterDTO.class))).thenReturn(responseDTO);

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isBadRequest());

    }

    @Test
    void testRegister_maxRateLimit_shouldReturnTooManyRequest() throws Exception {

        RateLimitingService.RateLimitResult rateLimitResult = new RateLimitingService.RateLimitResult(false, 100, 10);
        when(rateLimitingService.checkRegisterByIp(any(HttpServletRequest.class))).thenReturn(rateLimitResult);
        when(inviteCodeService.validateInviteCode("INVITE123")).thenReturn(false);
        when(authService.register(any(UserRegisterDTO.class))).thenReturn(responseDTO);

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void testLogin_success_shouldReturnUserData() throws Exception {

        RateLimitingService.RateLimitResult rateLimitResult = new RateLimitingService.RateLimitResult(true, 99, 10);

        when(rateLimitingService.checkLoginByIp(any(HttpServletRequest.class))).thenReturn(rateLimitResult);
        when(rateLimitingService.checkLoginByUser(eq("carla123"))).thenReturn(rateLimitResult);
        when(authService.login(any(AuthRequestDTO.class))).thenReturn(authResponseDTO);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginDTO)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("secretToken"))
                .andExpect(jsonPath("$.refreshToken").value("secretToken"))
                .andExpect(jsonPath("$.username").value("carla123"))
                .andExpect(jsonPath("$.email").value("carla@email.com"))
                .andExpect(jsonPath("$.fullName").value("Carla Test"))
                .andExpect(header().string("X-RateLimit-IP-Remaining", "99"))
                .andExpect(header().string("X-RateLimit-User-Remaining", "99"));

    }

    @Test
    void testLogin_rateLimitByIpExceeded_shouldReturnTooManyRequest() throws Exception {

        RateLimitingService.RateLimitResult ipLimitExceeded = new RateLimitingService.RateLimitResult(false, 0, 60);
        when(rateLimitingService.checkLoginByIp(any(HttpServletRequest.class)))
                .thenReturn(ipLimitExceeded);

    
        when(rateLimitingService.checkLoginByUser(anyString()))
                .thenReturn(new RateLimitingService.RateLimitResult(true, 5, 60));

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginDTO)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void testLogin_rateLimitByUserExceeded_shouldReturnTooManyRequest() throws Exception {

        when(rateLimitingService.checkLoginByIp(any(HttpServletRequest.class)))
                .thenReturn(new RateLimitResult(true, 10, 60));

        RateLimitingService.RateLimitResult userLimitExeeded =
        new RateLimitingService.RateLimitResult(false,0, 60);
        when(rateLimitingService.checkLoginByUser(anyString()))
                .thenReturn(userLimitExeeded);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginDTO)))
                .andExpect(status().isTooManyRequests());
    }

}


