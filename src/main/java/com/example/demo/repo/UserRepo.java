package com.example.demo.repo;

import com.example.demo.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */
public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
