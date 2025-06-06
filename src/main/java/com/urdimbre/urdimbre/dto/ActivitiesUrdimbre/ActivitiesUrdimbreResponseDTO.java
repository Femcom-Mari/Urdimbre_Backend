package com.urdimbre.urdimbre.dto.activitiesUrdimbre;

import java.time.LocalDate;
import java.time.LocalTime;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.urdimbre.urdimbre.model.Category;
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
    private String title;
    private String description;
    private Language language;
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate date;
    @JsonFormat(pattern = "HH:mm")
    private LocalTime startTime;
    @JsonFormat(pattern = "HH:mm")
    private LocalTime endTime;
    private Integer maxAttendees;

}
