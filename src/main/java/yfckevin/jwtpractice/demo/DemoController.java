package yfckevin.jwtpractice.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1.0/demo-controller")
public class DemoController {

    @GetMapping
    public ResponseEntity<String> sayOK(){
        return ResponseEntity.ok("OK from secured endpoint");
    }
}
