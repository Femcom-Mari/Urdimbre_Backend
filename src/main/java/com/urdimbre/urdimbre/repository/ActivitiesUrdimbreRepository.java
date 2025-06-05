package com.urdimbre.urdimbre.repository;


import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.Category;

@Repository
public interface ActivitiesUrdimbreRepository extends JpaRepository<ActivitiesUrdimbre, Integer> {


    List<ActivitiesUrdimbre> findAllByCategory(Category category);
}