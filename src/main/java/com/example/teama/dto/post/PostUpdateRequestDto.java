package com.example.teama.dto.post;

import com.example.teama.entity.Post;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class PostUpdateRequestDto {
    private String postTitle;
    private String postContent;

    @Builder
    public PostUpdateRequestDto(String postTitle, String postContent) {
        this.postTitle = postTitle;
        this.postContent = postContent;
    }

    public Post toEntity() {
        return Post.builder()
                .postTitle(postTitle)
                .postContent(postContent)
                .build();
    }
}
