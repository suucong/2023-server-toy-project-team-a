package com.example.teama.service;

import com.example.teama.dto.heart.HeartRequestDto;
import com.example.teama.entity.Heart;
import com.example.teama.entity.Post;
import com.example.teama.entity.User;
import com.example.teama.persistence.HeartRepository;
import com.example.teama.persistence.PostRepository;
import com.example.teama.persistence.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Role;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class HeartService {

    private HeartRepository heartRepository;
    private UserRepository userRepository;
    private PostRepository postRepository;


    // 좋아요 추가
    public void addHeart(HeartRequestDto requestDto) {
        User user = userRepository.findById(requestDto.getUserId().getId())
                .orElseThrow(() -> new RuntimeException("사용자 없음"));      // HeartRequestDto에서 userId를 가져와서 UserRepository에서 user 탐색
        Post post = postRepository.findById(requestDto.getPostId().getId())
                .orElseThrow(() -> new RuntimeException("게시물 없음"));      // HeartRequestDto에서 postId를 가져와서 PostRepository에서 post 탐색
        Heart heart = Heart.builder().user(user).post(post).build();        // user와 post를 찾았다면 Heart 엔터티를 생성합니다.
        heartRepository.save(heart);  // 생성된 Heart 엔터티를 HeartRepository를 통해 저장
    }

    // 좋아요 취소
    public void removeHeart(HeartRequestDto requestDto) {
        heartRepository.deleteByUserIdAndPostId(requestDto.getUserId(), requestDto.getPostId());    // HeartRequestDto에서 userId와 postId를 가져와서 해당하는 좋아요 삭제
    }
}