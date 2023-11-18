package com.example.teama.persistence;

import com.example.teama.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PostRepository extends JpaRepository<Post, Long>{
    List<Post> findAllByOrderByIdDesc();    // Using JPA Naming Convention


}
