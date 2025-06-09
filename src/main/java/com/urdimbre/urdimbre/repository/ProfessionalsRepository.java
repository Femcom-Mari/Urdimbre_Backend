package com.urdimbre.urdimbre.repository;

import com.urdimbre.urdimbre.model.Professional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProfessionalsRepository extends JpaRepository<Professional, Long> {

}
