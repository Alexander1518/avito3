package com.amr.project.model.entity;

import com.amr.project.model.enums.Gender;
import lombok.*;

import javax.persistence.*;
import java.util.Calendar;

@Entity
@Table(name = "user_info")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString(of = {"phone", "firstName", "lastName", "age", "gender", "birthday"})
public class UserInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, unique = true)
    private Long id;

    private String phone;
    private String firstName;
    private String lastName;
    private int age;
    private Gender gender;
    private Calendar birthday;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
}
