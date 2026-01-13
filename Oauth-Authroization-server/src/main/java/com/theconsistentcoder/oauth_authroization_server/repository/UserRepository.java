package com.theconsistentcoder.oauth_authroization_server.repository;

import com.theconsistentcoder.oauth_authroization_server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findbyEmail(String email);
}
