package com.urdimbre.urdimbre.repository;

import com.urdimbre.urdimbre.model.Professional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProfessionalRepository extends JpaRepository<Professional, Long> {
    // Puedes añadir métodos personalizados si lo necesitas
}
