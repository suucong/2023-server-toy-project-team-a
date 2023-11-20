package com.example.teama.controller;

import com.example.teama.dto.post.PostResponseDto;
import com.example.teama.dto.post.PostSaveRequestDto;
import com.example.teama.dto.post.PostUpdateRequestDto;
import com.example.teama.entity.User;
import com.example.teama.jwt.util.IfLogin;
import com.example.teama.jwt.util.LoginUserDto;
import com.example.teama.service.PostService;
import com.example.teama.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
//@Controller
//@RequestMapping("/posts/*")
public class PostController {
    private final PostService postService;
    private final UserService userService;

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
    public Long savePost(@IfLogin LoginUserDto loginUserDto, @RequestBody PostSaveRequestDto requestDto) {
        try {
            User user = userService.findByEmail(loginUserDto.getUserEmail());
            requestDto.setUser(user);

            return postService.save(requestDto);
        } catch (IllegalArgumentException e) {  // 해당 사용자가 없는 경우 post가 저장되지 않도록
            return -1L;
        }
    }

    // Update Post
    @PutMapping("/api/v1/post/{id}")
    public Long updatePost(@IfLogin LoginUserDto loginUserDto, @PathVariable Long id, @RequestBody PostUpdateRequestDto requestDto) {
        try {
            User user = userService.findByEmail(loginUserDto.getUserEmail());

            return postService.update(id, requestDto);
        } catch (IllegalArgumentException e) {  // 해당 사용자가 없는 경우 post가 수정되지 않도록
            return -1L;
        }
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
    public Long deletePost(@IfLogin LoginUserDto loginUserDto, @PathVariable Long postId) {
        try {
            User user = userService.findByEmail(loginUserDto.getUserEmail());

            postService.delete(postId);
            return postId;
        } catch (IllegalArgumentException e) {  // 해당 사용자가 없는 경우 post가 삭제되지 않도록
            return -1L;
        }
    }
}
