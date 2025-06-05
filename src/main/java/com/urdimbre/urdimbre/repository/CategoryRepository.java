package com.urdimbre.urdimbre.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.urdimbre.urdimbre.model.Category;


@Repository
public interface CategoryRepository extends JpaRepository<Category, Integer> {

}
