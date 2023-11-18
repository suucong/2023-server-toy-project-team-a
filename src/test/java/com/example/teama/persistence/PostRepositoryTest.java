package com.example.teama.persistence;

import com.example.teama.entity.Post;
import com.example.teama.entity.User;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.assertThat;
import java.util.Optional;

@RunWith(SpringRunner.class)
@SpringBootTest
@Transactional
@Rollback(true)
public class PostRepositoryTest {
    @Autowired
    PostRepository postRepository;
    @Autowired
    UserRepository userRepository;

    @Test
    @DisplayName("savePost")
    public void savePost() {
        // given
        User user = User.builder()
                .userEmail("email")
                .userPassword("password")
                .userPhone("phone")
                .userNickname("nickname")
                .build();

        userRepository.save(user);

        String postTitle = "title";
        String postContent = "content";

        postRepository.save(Post.builder()
                .postTitle(postTitle)
                .postContent(postContent)
                .user(user)
                .build());

        // when
        Optional<Post> optionalPost = postRepository.findById(Long.valueOf(0));

        // then
        if(optionalPost.isEmpty() != true) {
            Post post = optionalPost.get();
            assertThat(post.getPostTitle()).isEqualTo(postTitle);
            assertThat(post.getUser().getId()).isEqualTo(user.getId());
            assertThat(post.getPostContent()).isEqualTo(postContent);
        }
    }
}
