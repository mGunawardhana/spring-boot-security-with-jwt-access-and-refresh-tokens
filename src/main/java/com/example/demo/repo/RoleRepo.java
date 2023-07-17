package com.example.demo.repo;

import com.example.demo.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;
/**
 * @developed-by : mGunawardhana
 * @contact : 071-9043372
 */
public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
