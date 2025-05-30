package com.urdimbre.urdimbre.service.Activities;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.model.Activities;
import com.urdimbre.urdimbre.repository.ActivitiesRepository;

import lombok.AllArgsConstructor;


@Service
@AllArgsConstructor
public class ActivitiesService {


    private final ActivitiesRepository activitiesRepository;

    public ResponseEntity<Object> createActivity (Activities activities) {
        return new ResponseEntity<>(activitiesRepository.save(activities), HttpStatus.CREATED);
    }

}
