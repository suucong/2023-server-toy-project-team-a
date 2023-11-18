package com.example.teama.entity;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table (name = "TBL_REPLY")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Reply {
    @Id
    @GeneratedValue
    @EqualsAndHashCode.Include
    private Long id;

    @ManyToOne @NotNull
    private User user;

    @ManyToOne @NotNull
    private Post post;

    @NotNull
    private String replyContent;

    @CreationTimestamp
    private LocalDateTime replyRegisterDate;

    @UpdateTimestamp
    private LocalDateTime replyUpdateDate;


  @Builder
    public Reply(User user, Post post, String replyContent) {
        this.user = user;
        this.post = post;
        this.replyContent = replyContent;
    }
}
