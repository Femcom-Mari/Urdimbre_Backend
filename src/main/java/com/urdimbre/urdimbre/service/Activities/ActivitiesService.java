package com.urdimbre.urdimbre.service.Activities;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.model.Activities;
import com.urdimbre.urdimbre.model.CategoryActivities;
import com.urdimbre.urdimbre.repository.ActivitiesRepository;
import com.urdimbre.urdimbre.repository.CategoryActivitiesRepository;

import lombok.AllArgsConstructor;


@Service
@AllArgsConstructor
public class ActivitiesService {


    private final ActivitiesRepository activitiesRepository;
    private final CategoryActivitiesRepository categoryActivitiesRepository;


    public ResponseEntity<Object> createActivity (Integer categoryId, Activities activities) {
        Optional<CategoryActivities> CategoryActivitiesOptional = categoryActivitiesRepository.findById(categoryId);
        activities.setCategoryActivities(CategoryActivitiesOptional.get());
        return new ResponseEntity<>(activitiesRepository.save(activities), HttpStatus.CREATED);
    }

}
