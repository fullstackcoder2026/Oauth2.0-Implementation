package com.theconsistentcoder.oauth_authroization_server.service;

import com.theconsistentcoder.oauth_authroization_server.entity.User;
import com.theconsistentcoder.oauth_authroization_server.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Transactional
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findbyEmail(email);
        if (user == null) {
        //   return null;
            throw  new UsernameNotFoundException("No User Found");
        } else {
            return new org.springframework.security.core.userdetails.User(
                    user.getEmail(),
                    user.getPassword(),
                    user.isEnabled(),
                    true,
                    true,
                    true,
                    getAuthorities(List.of(user.getRole()))
            );
        }
    }

    private Collection<? extends GrantedAuthority> getAuthorities(List<String> roles) {
        List<GrantedAuthority> authoritiesList = new ArrayList<>();
        for (String role: roles) {
            authoritiesList.add(new SimpleGrantedAuthority(role));
        }
            return  authoritiesList;
    }
}
