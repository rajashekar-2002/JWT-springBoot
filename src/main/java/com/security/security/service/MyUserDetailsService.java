package com.security.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.security.security.entity.Student;
import com.security.security.repo.StudentRepo;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private StudentRepo repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // UserDetails is an interface cannot return directly 
        // current user which we r auth-ing is principle
        Student object=repo.findByName(username);
        if(object==null){
            System.out.println(object);
            throw new UsernameNotFoundException("null object found");
        }

        // cannot directly return object
        // UserDetails is interface define a class
        return new UserPrincipal(object);
    }
    
}
