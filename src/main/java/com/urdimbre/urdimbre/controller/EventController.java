package com.urdimbre.urdimbre.controller;

import java.security.Principal;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.events.EventRequestDTO;
import com.urdimbre.urdimbre.dto.events.EventResponseDTO;
// import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.UserRepository;
import com.urdimbre.urdimbre.service.event.EventService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/events")
public class EventController {

    private final EventService eventService;
    // private final UserRepository userRepository;

    public EventController(EventService eventService, UserRepository userRepository) {
        this.eventService = eventService;
        // this.userRepository = userRepository;
    } 

        @PostMapping("/create")
    public ResponseEntity<EventResponseDTO> createEvent(@Valid @RequestBody EventRequestDTO dto,
                                                        Principal principal) {
        String username = principal.getName();
        EventResponseDTO response = eventService.createEvent(dto, username);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
 