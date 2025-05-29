package com.urdimbre.urdimbre.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.urdimbre.urdimbre.model.CategoryActivities;


@Repository
public interface CategoryActivitiesRepository extends JpaRepository<CategoryActivities, Integer> {

}
