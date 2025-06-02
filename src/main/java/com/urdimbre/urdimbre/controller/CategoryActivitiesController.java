package com.urdimbre.urdimbre.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.urdimbre.urdimbre.model.CategoryActivities;
import com.urdimbre.urdimbre.service.CategoryActivities.CategoryActivitiesService;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;


@Controller
@AllArgsConstructor
@RequestMapping("api/v1/categoryActivities")
public class CategoryActivitiesController {

    private final CategoryActivitiesService categoryActivitiesService;

    @PostMapping
    public ResponseEntity<Object> createCategoryActivities(@Valid @RequestBody CategoryActivities categoryActivities) {
        return categoryActivitiesService.createCategoryActivities(categoryActivities);
    }

}
