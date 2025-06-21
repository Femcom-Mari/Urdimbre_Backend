package com.urdimbre.urdimbre.dto.events;

import java.time.LocalDate;

import com.urdimbre.urdimbre.model.CategoryEvents;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventResponseDTO {

    private Long id;

    private String title;

    private String description;

    private LocalDate date;

    private CategoryEvents category;

    private String link;

    private String creatorUsername;

}
