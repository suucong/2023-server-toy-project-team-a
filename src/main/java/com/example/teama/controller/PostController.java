package com.example.teama.controller;

import com.example.teama.dto.post.PostResponseDto;
import com.example.teama.dto.post.PostSaveRequestDto;
import com.example.teama.dto.post.PostUpdateRequestDto;
import com.example.teama.service.PostService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
//@Controller
//@RequestMapping("/posts/*")
public class PostController {
    private final PostService postService;

//    @GetMapping("write")
//    public void goToWriteForm(){
//
//    }
//    @GetMapping("detail")
//    public void goToDetail(){
//
//    }
//    @GetMapping("list")
//    public void goToList(){
//
//    }

    // Save Post
    @PostMapping("/api/v1/post")
    public Long savePost(@RequestBody PostSaveRequestDto requestDto) {
        return postService.save(requestDto);
    }

    // Update Post
    @PutMapping("/api/v1/post/{id}")
    public Long updatePost(@PathVariable Long id, @RequestBody PostUpdateRequestDto requestDto) {
        return postService.update(id, requestDto);
    }

    // Read Post
    @GetMapping("/api/v1/post/{id}")
    public PostResponseDto findById(@PathVariable Long id) {
        return postService.findById(id);
    }

    // Read Post List
    @GetMapping("/api/v1/post")
    public List<PostResponseDto> findAllDesc() {
        return postService.findAllDesc();
    }

    // Delete Post
    @DeleteMapping("/api/v1/post/{postId}")
    public Long deletePost(@PathVariable Long postId) {
        postService.delete(postId);

        return postId;
    }
}
