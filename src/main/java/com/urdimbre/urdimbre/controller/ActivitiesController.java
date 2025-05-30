package com.urdimbre.urdimbre.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.urdimbre.urdimbre.model.Activities;
import com.urdimbre.urdimbre.service.Activities.ActivitiesService;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;


@AllArgsConstructor
@Controller
@RequestMapping("api/v1/activities")
public class ActivitiesController {

    private final ActivitiesService activitiesService;

    @PostMapping
    public ResponseEntity<Object> createActivity(@Valid @RequestBody Activities activities) {
        return activitiesService.createActivity(activities);
    }
}
