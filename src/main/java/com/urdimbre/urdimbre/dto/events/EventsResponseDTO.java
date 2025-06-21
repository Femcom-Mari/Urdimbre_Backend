package com.urdimbre.urdimbre.dto.events;

import com.urdimbre.urdimbre.model.CategoryEvents;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class EventsResponseDTO {

    private Long id;

    private String title;

    private String description;

    private CategoryEvents category;

    private String link;

}
