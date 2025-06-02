package com.urdimbre.urdimbre.service.CategoryActivities;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import com.urdimbre.urdimbre.model.CategoryActivities;
import com.urdimbre.urdimbre.repository.CategoryActivitiesRepository;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class CategoryActivitiesService {

    private final CategoryActivitiesRepository categoryActivitiesRepository;

    public ResponseEntity<Object> createCategoryActivities (CategoryActivities categoryActivities) {
        return new ResponseEntity<>(categoryActivitiesRepository.save(categoryActivities), HttpStatus.CREATED);
    }
}
