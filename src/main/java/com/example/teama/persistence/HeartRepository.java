package com.example.teama.persistence;

import com.example.teama.entity.Heart;
import com.example.teama.entity.Post;
import com.example.teama.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface HeartRepository extends JpaRepository<Heart, Long> {
    void deleteByUserIdAndPostId(User userId, Post postId);
}