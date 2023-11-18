package com.example.teama.dto.heart;

import com.example.teama.entity.Post;
import com.example.teama.entity.User;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class HeartRequestDto {
    private Post postId;
    private User userId;

    @Builder
    public HeartRequestDto(User userId, Post postId){
        this.postId = postId;
        this.userId = userId;
    }
}