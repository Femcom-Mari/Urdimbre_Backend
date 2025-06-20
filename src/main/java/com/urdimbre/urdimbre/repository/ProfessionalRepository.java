package com.urdimbre.urdimbre.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.urdimbre.urdimbre.model.Professional;

@Repository
public interface ProfessionalRepository extends JpaRepository<Professional, Long> {

}
