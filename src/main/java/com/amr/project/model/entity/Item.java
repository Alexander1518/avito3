package com.amr.project.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.math.BigDecimal;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "item")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Item {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", unique = true)
    private Long id;
    @Column(name = "name", unique = true)
    private String name;

    private BigDecimal basePrice;
    private BigDecimal price;
    private int count;
    private double rating;
    private String description;
    private int discount;

    @ManyToMany
    @JoinTable(name = "item_category",
    joinColumns = @JoinColumn(name = "item_id"),
    inverseJoinColumns = @JoinColumn(name = "category_id"))
    private Set<Category> categories;


    @ManyToOne(fetch = FetchType.LAZY)
    private CartItem cartItem;


    @ManyToMany
    @JoinTable(name = "item_image",
            joinColumns = @JoinColumn(name = "item_id"),
            inverseJoinColumns = @JoinColumn(name = "image_id"))
    private Set<Image> images;


    @OneToMany(
            mappedBy = "item",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private Set<Review> reviews;


    @ManyToMany(mappedBy = "items")
    private Set<Favorite> favorites;


    @ManyToMany(mappedBy = "itemsInOrder")
    private Set<Order> orders;

    @ManyToOne(fetch = FetchType.LAZY)
    private Shop shop;



    private boolean isModerated = false;
    private boolean isModerateAccept;
    private String moderatedRejectReason;
    private boolean isPretendedToBeDeleted;
}
