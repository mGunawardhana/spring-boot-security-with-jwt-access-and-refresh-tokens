package com.example.demo.domain;

import java.util.ArrayList;
import java.util.Collection;

/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */
public class User {
    private Long id;
    private String name;
    private String username;
    private String password;
    private final Collection<Role> roles = new ArrayList<>();
}
