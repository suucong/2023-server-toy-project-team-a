package com.example.teama.dto.post;

import com.example.teama.entity.Post;
import com.example.teama.entity.User;
import lombok.Getter;

@Getter
public class PostResponseDto {
    private final Long id;
    private final User user;
    private final String postTitle;
    private final String postContent;

    public PostResponseDto(Post post) {
        this.id = post.getId();
        this.user = post.getUser();
        this.postTitle = post.getPostTitle();
        this.postContent = post.getPostContent();
    }
}
