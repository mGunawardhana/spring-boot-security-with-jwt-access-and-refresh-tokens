package com.example.demo.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ManyToAny;

import java.util.ArrayList;
import java.util.Collection;

/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String username;
    private String password;
    @ManyToAny(fetch = FetchType.EAGER)
    private final Collection<Role> roles = new ArrayList<>();
}
