package com.amr.project.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name = "city")
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class City {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "name")
    private String name;


    @OneToMany(
            mappedBy = "city",
            cascade = {CascadeType.PERSIST,
                    CascadeType.MERGE,
                    CascadeType.REFRESH,
                    CascadeType.DETACH},
            orphanRemoval = true
    )
    private Set<Address> addresses;

    @ManyToOne(fetch = FetchType.LAZY)
    private Country country;

    public City(Long id) {
        this.id = id;
    }
}