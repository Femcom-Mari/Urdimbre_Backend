package com.urdimbre.urdimbre.controller;

import java.security.Principal;
import java.time.LocalDate;
import java.util.List;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
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

    @GetMapping
    public ResponseEntity<List<EventResponseDTO>> getAllEvents() {
        return ResponseEntity.ok(eventService.getAllEvents());
    }

    @GetMapping("/category/{category}")
    public ResponseEntity<List<EventResponseDTO>> getByCategory(@PathVariable String category) {
        return ResponseEntity.ok(eventService.getEventsByCategory(category));
    }

    @GetMapping("/date/{date}")
    public ResponseEntity<List<EventResponseDTO>> getByDate(@PathVariable @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        return ResponseEntity.ok(eventService.getEventsByDate(date));
    }

    @GetMapping("/{id}")
public ResponseEntity<EventResponseDTO> getById(@PathVariable Long id) {
    EventResponseDTO dto = eventService.getById(id);
    return ResponseEntity.ok(dto);
}
    @PutMapping("/{id}")
    public ResponseEntity<EventResponseDTO> updateEventById(@PathVariable Long id,
                                                        @RequestBody EventRequestDTO dto,
                                                        Principal principal) {
        String username = principal.getName();
        EventResponseDTO updated = eventService.updateEventById(id, dto, username);
        return ResponseEntity.ok(updated);
    }

        @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteEventById(@PathVariable Long id, Principal principal) {
        String username = principal.getName();
        eventService.deleteEventById(id, username);
        return ResponseEntity.noContent().build();
    }

}
 