package yfckevin.jwtpractice.service;

import org.springframework.http.ResponseEntity;

public interface UserService {
//    public ResponseEntity<?> createUser(Register register);

    public ResponseEntity<?> getAllUser();

    public ResponseEntity<?> getOneUser(String id);
}
