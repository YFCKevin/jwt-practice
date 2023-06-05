package yfckevin.jwtpractice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import yfckevin.jwtpractice.service.UserService;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/v1/users")
@RequiredArgsConstructor
public class UserController {
    private UserService userService;

    @GetMapping(value = "/")
    public ResponseEntity<?> getAllUser() {
        return userService.getAllUser();
    }

    @GetMapping(value = "/{id}")
    public ResponseEntity<?> getOneUser(@PathVariable String id, Principal principal) {
        String userId = principal.getName();
        if (!id.equals(userId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "get another user account is forbidden"));
        }
        return userService.getOneUser(id);
    }
}
