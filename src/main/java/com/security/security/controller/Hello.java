package com.security.security.controller;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
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

import jakarta.servlet.http.HttpServletRequest;


@Controller
public class Hello {
    @Autowired
    private StudentRepo studentRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;


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
    public List<Student> add(@RequestBody Student student){
        student.setPassword(passwordEncoder.encode(student.getPassword()));
        students.add(student);
        return students;
    }

    @GetMapping("/getCsrf")
    public CsrfToken getcsrf(HttpServletRequest http){
        return (CsrfToken) http.getAttribute("_csrf");
    }

    @GetMapping("/all")
    public String add(Model model){
        model.addAttribute("msg", students);
        return "home";
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }


    @PostMapping("/login")
    public String login(@RequestBody Student student){
        // authentiacte using authentiacte maanger -> uses auth provider and save in authentication
        //create a bean of authentiacte manager and now we can hold object

        Authentication authentication = authenticationManager
                                        .authenticate(new UsernamePasswordAuthenticationToken(
                                                student.getName(), student.getPassword()));
        if(authentication.isAuthenticated()){
            return "pass";
        }else{
            return "failed";
        }

    }



}



