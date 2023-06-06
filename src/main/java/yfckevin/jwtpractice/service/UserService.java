package yfckevin.jwtpractice.service;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

public interface UserService {

    public ResponseEntity<?> getAllUser();

    public ResponseEntity<?> getOneUser(String id);
}
