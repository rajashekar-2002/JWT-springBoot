package com.security.security.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.security.entity.Student;

public interface StudentRepo extends JpaRepository<Student,Integer> {
    Student findByName(String name);
    
}
