package com.amr.project.model.entity;

import com.amr.project.model.enums.Roles;
import lombok.*;
import org.hibernate.Hibernate;
import org.jboss.aerogear.security.otp.api.Base32;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.*;

@Entity
@Getter
@Setter
//@RequiredArgsConstructor
@Builder
@AllArgsConstructor
//@ToString(of = {"id", "email", "username", "password"})
@ToString
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, unique = true)
    @ToString.Exclude
    private Long id;

    @Column(name = "email", unique = true)
    @ToString.Exclude
    private String email;

    @Column(name = "username", unique = true)
    @ToString.Exclude
    private String username;
    @ToString.Exclude
    private String password;
    private boolean activate;
    private String activationCode;
    private boolean isUsing2FA;
    private String secret;


    public User() {
        this.secret = Base32.random();
    }

    @Enumerated(EnumType.STRING)
    private Roles role;


    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL,
            fetch = FetchType.LAZY, optional = false)
    @ToString.Exclude
    private UserInfo userInfo;


    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL,
            fetch = FetchType.LAZY, optional = false)
    @ToString.Exclude
    private Favorite favorite;


    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private Address address;

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "user_id")
    @ToString.Exclude
    private List<Image> images;


    @OneToMany(
            mappedBy = "user",
            cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE,
                    CascadeType.DETACH,
                    CascadeType.REFRESH},
            orphanRemoval = true)
    @ToString.Exclude
    private List<Coupon> coupons;


    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @ToString.Exclude
    private List<CartItem> cart;


    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @ToString.Exclude
    private List<Order> orders;


    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @ToString.Exclude
    private List<Review> reviews;


    @OneToMany(
            mappedBy = "user",
            cascade = {
                    CascadeType.MERGE,
                    CascadeType.PERSIST,
                    CascadeType.DETACH,
                    CascadeType.REFRESH},
            orphanRemoval = true
    )
    @ToString.Exclude
    private Set<Shop> shops;


    @OneToMany(cascade = CascadeType.ALL,
            orphanRemoval = true)
    @JoinColumn(name = "user_id")
    @ToString.Exclude
    private Set<Discount> discounts;


    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @ToString.Exclude
    private Set<Message> messages;


    @ManyToMany(cascade = {CascadeType.MERGE, CascadeType.PERSIST})
    @JoinTable(name = "user_chat",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "chat_id"))
    @ToString.Exclude
    private Set<Chat> chats;


    @OneToMany(
            mappedBy = "user",
            cascade = {CascadeType.MERGE,
                    CascadeType.PERSIST,
                    CascadeType.REFRESH,
                    CascadeType.DETACH},
            orphanRemoval = true
    )
    @ToString.Exclude
    private Set<Feedback> feedbacks;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new HashSet<Roles>(Arrays.asList(role));
    }

    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL
    )
    @ToString.Exclude
    private List<Item> items;

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return activate;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        User user = (User) o;
        return id != null && Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
