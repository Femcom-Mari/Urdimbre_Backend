package com.urdimbre.urdimbre.service.event;

import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.events.EventRequestDTO;
import com.urdimbre.urdimbre.dto.events.EventResponseDTO;
import com.urdimbre.urdimbre.mapper.EventMapper;
import com.urdimbre.urdimbre.model.Event;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.EventRepository;
import com.urdimbre.urdimbre.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EventServiceImpl implements EventService {

    private final EventRepository eventRepository;
    private final UserRepository userRepository;
    private final EventMapper eventMapper;

    @Override
    public EventResponseDTO createEvent(EventRequestDTO dto, String creatorUsername) {
        User creator = getUser(creatorUsername);
        Event event = eventMapper.toEntity(dto, creator);
        eventRepository.save(event);
        return eventMapper.toDto(event);
    }

    private User getUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
    }

    // private Event getEvent(Long id) {
    //     return eventRepository.findById(id)
    //             .orElseThrow(() -> new RuntimeException("Evento no encontrado"));
    // }


}
