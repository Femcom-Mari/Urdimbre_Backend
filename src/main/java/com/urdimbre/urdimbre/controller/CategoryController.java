package com.urdimbre.urdimbre.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.urdimbre.urdimbre.model.Category;
import com.urdimbre.urdimbre.service.Category.CategoryService;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;


@Controller
@AllArgsConstructor
@RequestMapping("api/v1/category")
public class CategoryController {

    private final CategoryService categoryService;

    @PostMapping
    public ResponseEntity<Object> createCategory(@Valid @RequestBody Category category) {
        return categoryService.createCategory(category);
    }

}
