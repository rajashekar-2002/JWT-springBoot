package com.security.security.controller;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.security.security.entity.Student;
import com.security.security.repo.StudentRepo;
import com.security.security.service.JwtService;

import jakarta.servlet.http.HttpServletRequest;


@Controller
public class Hello {
    @Autowired
    private StudentRepo studentRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;


    private List<Student> students=new ArrayList<>(List.of(
        new Student(1,"raju","js"),
        new Student(2,"chotu","react"),
        new Student(3,"ganiger","spring")
        ));


    @GetMapping("/")
    public String hello(){
        return "hello";
    }



    @PostMapping("/add")
    public HttpEntity<?> add(@RequestBody Student student){
        student.setPassword(passwordEncoder.encode(student.getPassword()));
        studentRepo.save(student);
        return new HttpEntity<>(student);
    }

    @GetMapping("/getCsrf")
    public CsrfToken getcsrf(HttpServletRequest http){
        return (CsrfToken) http.getAttribute("_csrf");
    }

    @GetMapping("/all")
    public HttpEntity<?> all(Model model){
        List<Student> list=studentRepo.findAll();
        return new HttpEntity<>(list);
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }


    @PostMapping("/token")
    public ResponseEntity<?> login(@RequestBody Student student){
        // authentiacte using authentiacte maanger -> uses auth provider and save in authentication
        //create a bean of authentiacte manager and now we can hold object

        Authentication authentication = authenticationManager
                                        .authenticate(new UsernamePasswordAuthenticationToken(
                                                student.getName(), student.getPassword()));
        if(authentication.isAuthenticated()){
            String token=jwtService.getToken(student.getName());
            return ResponseEntity.ok(token);
        }else{
            return ResponseEntity.notFound().build();
        }

    }



}



