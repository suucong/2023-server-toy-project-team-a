package com.example.teama.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.Length;

@Entity
@Table (name = "TBL_REFRESH_TOKEN")
@NoArgsConstructor
@Getter
@Setter
public class RefreshToken {
    @Id
    @GeneratedValue
    @Column(name = "id")
    private Long id;

//    private Long memberId;

    @ManyToOne(fetch = FetchType.LAZY, cascade = {CascadeType.PERSIST})
    private User user; // User 엔티티를 참조하는 필드


    @Column(length = 300)
    private String value;


}