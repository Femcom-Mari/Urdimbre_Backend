package com.urdimbre.urdimbre.dto.ActivitiesUrdimbre;

import java.time.LocalDateTime;
import java.util.Locale.Category;

import com.urdimbre.urdimbre.model.Language;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ActivitiesUrdimbreResponseDTO {


     private Category category;
    private Integer activityName;
    private String description;
    private Language language;
    private String date;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private Integer maxAttendees;

}
