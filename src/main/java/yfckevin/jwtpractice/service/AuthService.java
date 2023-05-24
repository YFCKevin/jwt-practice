package yfckevin.jwtpractice.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import yfckevin.jwtpractice.repository.UserRepository;

import java.util.List;

@Service
public class AuthService implements UserDetailsService {

    @Autowired
    private UserRepository userRepo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepo
                .findByEmail(email)
                .map(v -> new User(
                        v.getUsername(),
                        v.getPassword(),
                        List.of(new SimpleGrantedAuthority(v.getEmail()))
                ))
                .orElseThrow(() -> new UsernameNotFoundException("email not found"));
    }
}
