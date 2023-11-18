package com.example.teama.persistence;

import com.example.teama.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserEmail(String userEmail);


    //현지
   // User findByUserEmail(String userEmail);
    User findByUserNickname(String userNickname);
    User findByUserPhone(String userPhone);
    User findByUserPassword(String userPassword);
}
