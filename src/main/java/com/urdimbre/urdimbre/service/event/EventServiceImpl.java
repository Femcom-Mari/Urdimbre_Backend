package com.urdimbre.urdimbre.service.event;

import java.time.LocalDate;
import java.util.List;
import org.springframework.stereotype.Service;
import com.urdimbre.urdimbre.dto.events.EventRequestDTO;
import com.urdimbre.urdimbre.dto.events.EventResponseDTO;
import com.urdimbre.urdimbre.exception.BadRequestException;
import com.urdimbre.urdimbre.exception.DuplicateResourceException;
import com.urdimbre.urdimbre.exception.ResourceNotFoundException;
import com.urdimbre.urdimbre.exception.UnauthorizedActionException;
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

        boolean exists = eventRepository.existsByLink(dto.getLink());
        if (dto.getLink() == null || dto.getLink().isBlank()) {
            throw new BadRequestException("Event link cannot be empty.");
        }
        if (exists) {
            throw new DuplicateResourceException("An event with the same link already exists.");
        }
        if (dto.getDate().isBefore(LocalDate.now())) {
            throw new BadRequestException("Event date cannot be in the past.");
        }

        Event event = eventMapper.toEntity(dto, creator);
        eventRepository.save(event);
        return eventMapper.toDto(event);
    }

    @Override
    public List<EventResponseDTO> getEventsByCategory(String categoryName) {
        CategoryEvents category;
        try {
            category = CategoryEvents.valueOf(categoryName.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid category: " + categoryName);
        }
        return eventRepository.findByCategory(category)
                .stream()
                .map(eventMapper::toDto)
                .toList();
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
                .orElseThrow(() -> new ResourceNotFoundException("Event", "id", id));

        return eventMapper.toDto(event);
    }

    private User getUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "Username", username));
    }

    @Override
    public EventResponseDTO updateEventById(Long id, EventRequestDTO dto, String username) {
        Event event = getEvent(id);

        if (!event.getCreator().getUsername().equals(username)) {
            throw new UnauthorizedActionException("You do not have permission to edit this event");
        }
        if (dto.getDate().isBefore(LocalDate.now())) {
            throw new BadRequestException("Event date cannot be in the past.");
        }
        if (dto.getLink() == null || dto.getLink().isBlank()) {
            throw new BadRequestException("Event link cannot be empty.");
        }
        eventMapper.updateEventFromDto(event, dto);
        eventRepository.save(event);
        return eventMapper.toDto(event);
    }

    @Override
    public void deleteEventById(Long id, String username) {
        Event event = getEvent(id);

        if (!event.getCreator().getUsername().equals(username)) {
            throw new UnauthorizedActionException("You do not have permission to delete this event");
        }

        eventRepository.delete(event);
    }

    private Event getEvent(Long id) {
        return eventRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Event", "id", id));
    }

}
