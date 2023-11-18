package com.example.teama.controller;

import com.example.teama.dto.heart.HeartRequestDto;
import com.example.teama.service.HeartService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/heart")
public class HeartController {
    private HeartService heartService;

    // 좋아요 추가
    // HeartService를 이용하여 좋아요 추가
    @PutMapping("/{postid}")
    public String addHeart(@RequestBody HeartRequestDto requestDto) {
        heartService.addHeart(requestDto); //addHeart 메서드 호출하여 좋아요 추가
        return "Add Heart";
    }

    // 좋아요 삭제
    // HeartService를 이용하여 좋아요 삭제
    @DeleteMapping("/{postId}")
    public String removeHeart(@RequestBody HeartRequestDto requestDto) {
        heartService.removeHeart(requestDto); //removeHeart 메서드 호출하여 좋아요 삭제
        return "Delete Heart";
    }
}