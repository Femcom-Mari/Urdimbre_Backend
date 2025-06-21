package com.urdimbre.urdimbre.service.event;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import com.urdimbre.urdimbre.dto.events.EventRequestDTO;
import com.urdimbre.urdimbre.dto.events.EventResponseDTO;
import com.urdimbre.urdimbre.mapper.EventMapper;
import com.urdimbre.urdimbre.model.CategoryEvents;
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

    @Override
    public List<EventResponseDTO> getEventsByCategory(String categoryName) {
        CategoryEvents category = CategoryEvents.valueOf(categoryName);
        return eventRepository.findByCategory(category)
                .stream()
                .map(eventMapper::toDto)
                .toList();
    }

    @Override
    public List<EventResponseDTO> getEventByCreator(String creatorUser) {
        User creator = getUser(creatorUser);
        List<Event> events = eventRepository.findByCreator(creator);
        return events.stream()
                .map(eventMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    public List<EventResponseDTO> getEventsByDate(LocalDate date) {
        return eventRepository.findByDate(date)
                .stream()
                .map(eventMapper::toDto)
                .toList();
    }

    @Override
    public List<EventResponseDTO> getAllEvents() {
        return eventRepository.findAll().stream()
                .map(eventMapper::toDto)
                .toList();
    }

    @Override
    public EventResponseDTO getById(Long id) {
        Event event = eventRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Evento no encontrado"));

        return eventMapper.toDto(event);
    }

    private User getUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
    }

}
