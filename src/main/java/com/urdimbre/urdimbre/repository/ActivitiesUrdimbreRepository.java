package com.urdimbre.urdimbre.repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.Category;
import com.urdimbre.urdimbre.model.Language;

@Repository
public interface ActivitiesUrdimbreRepository extends JpaRepository<ActivitiesUrdimbre, Long> {

    Optional<ActivitiesUrdimbre> findByTitle(String title);

    // ================================
    // MÉTODOS QUE USA TU SERVICIO (con All)
    // ================================

    List<ActivitiesUrdimbre> findAllByCategoryOrderByDateAsc(Category category);

    List<ActivitiesUrdimbre> findAllByDate(LocalDate date);

    List<ActivitiesUrdimbre> findAllByLanguage(Language language);

    List<ActivitiesUrdimbre> findAllByDateGreaterThanEqual(LocalDate date);

    List<ActivitiesUrdimbre> findAllByTitleContainingIgnoreCase(String title);

    // ================================
    // MÉTODOS ADICIONALES (sin All)
    // ================================

    List<ActivitiesUrdimbre> findByCategory(Category category);

    Page<ActivitiesUrdimbre> findByCategory(Category category, Pageable pageable);

    List<ActivitiesUrdimbre> findByDate(LocalDate date);

    Page<ActivitiesUrdimbre> findByDate(LocalDate date, Pageable pageable);

    List<ActivitiesUrdimbre> findByDateBetween(LocalDate startDate, LocalDate endDate);

    Page<ActivitiesUrdimbre> findByDateBetween(LocalDate startDate, LocalDate endDate, Pageable pageable);

    List<ActivitiesUrdimbre> findByLanguage(Language language);

    Page<ActivitiesUrdimbre> findByLanguage(Language language, Pageable pageable);

    List<ActivitiesUrdimbre> findByCategoryAndDate(Category category, LocalDate date);

    List<ActivitiesUrdimbre> findByCategoryAndLanguage(Category category, Language language);

    List<ActivitiesUrdimbre> findByTitleContainingIgnoreCase(String title);

    Page<ActivitiesUrdimbre> findByTitleContainingIgnoreCase(String title, Pageable pageable);

    List<ActivitiesUrdimbre> findByDescriptionContainingIgnoreCase(String description);

    List<ActivitiesUrdimbre> findByDateGreaterThanEqual(LocalDate date);

    Page<ActivitiesUrdimbre> findByDateGreaterThanEqual(LocalDate date, Pageable pageable);

    List<ActivitiesUrdimbre> findByDateLessThan(LocalDate date);

    List<ActivitiesUrdimbre> findAllByOrderByDateAsc();

    List<ActivitiesUrdimbre> findAllByOrderByDateDesc();

    List<ActivitiesUrdimbre> findByCategoryOrderByDateAsc(Category category);

    // ================================
    // MÉTODOS DE EXISTENCIA Y CONTEO
    // ================================

    boolean existsByDate(LocalDate date);

    boolean existsByTitle(String title);

    boolean existsByCategoryAndDate(Category category, LocalDate date);

    long countByCategory(Category category);

    long countByDate(LocalDate date);

    long countByLanguage(Language language);

    long countByDateGreaterThanEqual(LocalDate date);

    long countByDateBetween(LocalDate startDate, LocalDate endDate);

    // ================================
    // CONSULTAS @Query NECESARIAS
    // ================================

    @Query("SELECT a FROM ActivitiesUrdimbre a WHERE a.maxAttendees > " +
            "(SELECT COUNT(att) FROM Attendance att WHERE att.activityId = a AND att.status = 'CONFIRMED')")
    List<ActivitiesUrdimbre> findActivitiesWithAvailableCapacity();

    @Query("SELECT a FROM ActivitiesUrdimbre a WHERE a.maxAttendees > " +
            "(SELECT COUNT(att) FROM Attendance att WHERE att.activityId = a AND att.status = 'CONFIRMED')")
    Page<ActivitiesUrdimbre> findActivitiesWithAvailableCapacity(Pageable pageable);

    @Query("SELECT a FROM ActivitiesUrdimbre a WHERE " +
            "LOWER(a.title) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(a.description) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<ActivitiesUrdimbre> findByTitleOrDescriptionContaining(@Param("searchTerm") String searchTerm);

    @Query("SELECT a FROM ActivitiesUrdimbre a WHERE " +
            "LOWER(a.title) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(a.description) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<ActivitiesUrdimbre> findByTitleOrDescriptionContaining(@Param("searchTerm") String searchTerm,
            Pageable pageable);
}