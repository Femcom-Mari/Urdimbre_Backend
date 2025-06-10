package com.urdimbre.urdimbre.repository;

import com.urdimbre.urdimbre.model.MapMarker;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MapMarkerRepository extends JpaRepository<MapMarker, Long> {
    // Puedes añadir métodos personalizados si lo necesitas
}
