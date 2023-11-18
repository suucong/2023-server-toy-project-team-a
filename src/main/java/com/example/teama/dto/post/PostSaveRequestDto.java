package com.example.teama.dto.post;

import com.example.teama.entity.Post;
import com.example.teama.entity.User;
import lombok.Builder;
import lombok.NoArgsConstructor;


@NoArgsConstructor
public class PostSaveRequestDto {
    private User user;
    private String postTitle;
    private String postContent;

    @Builder
    public PostSaveRequestDto(User user, String postTitle, String postContent) {
        this.user = user;
        this.postTitle = postTitle;
        this.postContent = postContent;
    }

    public Post toEntity() {
        return Post.builder()
                .user(user)
                .postTitle(postTitle)
                .postContent(postContent)
                .build();
    }
}
