package com.urdimbre.urdimbre.unit.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
// import org.junit.jupiter.api.extension.ExtendWith;
// import org.mockito.Mock;
// import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
// import org.springframework.test.context.bean.override.mockito.MockitoBean;
// import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import com.urdimbre.urdimbre.config.TestSecurityConfig;
import com.urdimbre.urdimbre.controller.AuthController;
import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.repository.UserRepository;
import com.urdimbre.urdimbre.security.service.RateLimitingService;
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

    @Test
    void testRegister_success() throws Exception {
        // Arrange
        UserRegisterDTO dto = UserRegisterDTO.builder()
                .username("carla123")
                .firstName("Carla")
                .lastName("Gómez")
                .pronouns(Set.of("Ella"))
                .password("Password1@")
                .email("carla@email.com")
                .inviteCode("INVITE123")
                .build();

        UserResponseDTO responseDTO = new UserResponseDTO();
            responseDTO.setId(1L);
            responseDTO.setUsername("carla123");
            responseDTO.setEmail("carla@email.com");
            responseDTO.setFullName("Carla Test");
            responseDTO.setPronouns(Set.of("Ella"));
            responseDTO.setStatus("ACTIVE");
            responseDTO.setCreatedAt("2025-06-18T12:00:00Z");
            responseDTO.setRoles(List.of("USER"));

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
 
}
