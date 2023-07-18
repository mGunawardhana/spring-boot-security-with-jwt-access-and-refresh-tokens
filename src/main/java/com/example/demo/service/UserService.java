package com.example.demo.service;

import com.example.demo.domain.Role;
import com.example.demo.domain.User;
import org.springframework.stereotype.Service;


import java.util.List;

/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */

@Service
public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);

    List<User> getUsers();
}
