package com.example.teama.controller;

import com.example.teama.dto.post.PostSaveRequestDto;
import com.example.teama.dto.post.PostUpdateRequestDto;
import com.example.teama.entity.Post;
import com.example.teama.entity.User;
import com.example.teama.persistence.PostRepository;
import com.example.teama.persistence.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class PostControllerTest {
    @Autowired
    private PostRepository postRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @Transactional
    @DisplayName("savePost() 테스트")
    public void savePost() throws Exception {
        User user = User.builder()
                .userEmail("email")
                .userPassword("password")
                .userPhone("phone")
                .userNickname("nickname")
                .build();

        userRepository.save(user);

        String postTitle = "title";
        String postContent = "content";

        PostSaveRequestDto requestDto = PostSaveRequestDto.builder()
                .user(user)
                .postTitle(postTitle)
                .postContent(postContent)
                .build();

        String content = objectMapper.writeValueAsString(requestDto);

        mockMvc.perform(post("/api/v1/post")
                .content(content)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string("1"))
                .andDo(print());
    }

    @Test
    @Transactional
    @DisplayName("updatePost() 테스트")
    public void updatePost() throws Exception {
        User user = User.builder()
                .userEmail("email")
                .userPassword("password")
                .userPhone("phone")
                .userNickname("nickname")
                .build();

        userRepository.save(user);

        Post savedPosts = postRepository.save(Post.builder()
                .user(user)
                .postTitle("title")
                .postContent("content")
                .build());

        Long updateId = savedPosts.getId();
        String expectedTitle = "title2";
        String expectedContent = "content2";

        PostUpdateRequestDto requestDto = PostUpdateRequestDto.builder()
                .postTitle(expectedTitle)
                .postContent(expectedContent)
                .build();

        String content = objectMapper.writeValueAsString(requestDto);

        mockMvc.perform(put("/api/v1/post/{id}", updateId)
                .content(content)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string("1"))
                .andDo(print());
    }

    @Test
    @Transactional
    @DisplayName("findById() 테스트")
    public void findById() throws Exception {
        User user = User.builder()
                .userEmail("email")
                .userPassword("password")
                .userPhone("phone")
                .userNickname("nickname")
                .build();

        userRepository.save(user);

        Post savedPosts = postRepository.save(Post.builder()
                .user(user)
                .postTitle("title")
                .postContent("content")
                .build());

        Long getPostId = savedPosts.getId();

        mockMvc.perform(get("/api/v1/post/{id}", getPostId)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    @Transactional
    @DisplayName("findAllDesc() 테스트")
    public void findAllDesc() throws Exception {
        User user = User.builder()
                .userEmail("email")
                .userPassword("password")
                .userPhone("phone")
                .userNickname("nickname")
                .build();

        userRepository.save(user);

        Post savedPosts = postRepository.save(Post.builder()
                .user(user)
                .postTitle("title")
                .postContent("content")
                .build());

        Post savedPosts2 = postRepository.save(Post.builder()
                .user(user)
                .postTitle("title2")
                .postContent("content2")
                .build());

        mockMvc.perform(get("/api/v1/post")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    @Transactional
    @DisplayName("deletePost() 테스트")
    public void deletePost() throws Exception {
        User user = User.builder()
                .userEmail("email")
                .userPassword("password")
                .userPhone("phone")
                .userNickname("nickname")
                .build();

        userRepository.save(user);

        Post savedPost = postRepository.save(Post.builder()
                .user(user)
                .postTitle("title")
                .postContent("content")
                .build());

        Long getPostId = savedPost.getId();

        mockMvc.perform(delete("/api/v1/post/{id}", getPostId)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print());
    }
}
