package com.urdimbre.urdimbre.service.event;

import java.time.LocalDate;
import java.util.List;

import com.urdimbre.urdimbre.dto.events.EventRequestDTO;
import com.urdimbre.urdimbre.dto.events.EventResponseDTO;

public interface EventService {

    EventResponseDTO createEvent (EventRequestDTO eventRequestDTO, String creatorUsername);

    List<EventResponseDTO> getEventsByCategory(String categoryName);

    List<EventResponseDTO> getEventsByDate(LocalDate date);

    List<EventResponseDTO> getAllEvents ();

    EventResponseDTO getById (Long id);


    EventResponseDTO updateEventById(Long id, EventRequestDTO dto, String username);

    void deleteEventById(Long id, String username);

}
