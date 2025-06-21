package com.urdimbre.urdimbre.repository;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.urdimbre.urdimbre.model.CategoryEvents;
import com.urdimbre.urdimbre.model.Event;
import com.urdimbre.urdimbre.model.User;

public interface EventRepository extends JpaRepository<Event, Long>{

    List<Event> findByCategory(CategoryEvents categoryName);
    List<Event> findByDate(LocalDate date);
    List<Event> findByCreator(User creator);
    
}
