package com.example.teama.entity;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table (name = "TBL_USER")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {
    @Id
    @GeneratedValue
    @EqualsAndHashCode.Include
    private Long id;

    @NotNull @Column(unique = true)
    private String userEmail;

    @NotNull
    private String userPassword;

    @NotNull
    private String userPhone;

    @NotNull @Column(unique = true)
    private String userNickname;

    @Column(name = "USER_STATUS", columnDefinition = "CHAR(1) DEFAULT '1' CHECK (USER_STATUS IN ('0', '1'))")
    private boolean userStatus;

    @CreationTimestamp
    private LocalDateTime userRegisterDate;

    @UpdateTimestamp
    private LocalDateTime userUpdateDate;

    @ManyToMany
    @JoinTable(name = "user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @Builder
    public User(String userEmail, String userPassword, String userPhone, String userNickname) {
        this.userEmail = userEmail;
        this.userPassword = userPassword;
        this.userPhone = userPhone;
        this.userNickname = userNickname;
    }

    public void addRole(Role role) {
        roles.add(role);
    }
}
