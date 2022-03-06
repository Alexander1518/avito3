package com.amr.project.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "message")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class Message {
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    private Chat chat;


    @Column(name = "user_to")
    private Long userIdTo;


    @Column(name = "user_from")
    private Long userIdFrom;

    private String textMessage;
    private boolean viewed;
}
