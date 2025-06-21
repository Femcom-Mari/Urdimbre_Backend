package com.urdimbre.urdimbre.mapper;

import org.springframework.stereotype.Component;

import com.urdimbre.urdimbre.dto.events.EventRequestDTO;
import com.urdimbre.urdimbre.dto.events.EventResponseDTO;
import com.urdimbre.urdimbre.model.Event;
import com.urdimbre.urdimbre.model.User;


@Component
public class EventMapper {


    public Event toEntity(EventRequestDTO dto, User creator) {
        return Event.builder()
                .title(dto.getTitle())
                .description(dto.getDescription())
                .date(dto.getDate())
                .category(dto.getCategory())
                .link(dto.getLink())
                .creator(creator)
                .build();
    }

    public EventResponseDTO toDto(Event event) {
        return EventResponseDTO.builder()
                .id(event.getId())
                .title(event.getTitle())
                .description(event.getDescription())
                .date(event.getDate())
                .category(event.getCategory())
                .link(event.getLink())
                .creatorUsername(event.getCreator() != null ? event.getCreator().getUsername() : null)
                .build();
    }

    public void updateEventFromDto(Event event, EventRequestDTO dto) {
        event.setTitle(dto.getTitle());
        event.setDescription(dto.getDescription());
        event.setDate(dto.getDate());
        event.setCategory(dto.getCategory());
        event.setLink(dto.getLink());
    }
}

