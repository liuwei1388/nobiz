package com.example.tls_demo.server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/service")
public class DemoController {

    @GetMapping("/test")
    public Map<String, Object> getTestInfo() {
        Map<String, Object> result = new HashMap<>();
        result.put("info", "success");
        return result;
    }
}
