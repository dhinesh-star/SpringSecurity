package com.eazybytes.controller;

import com.eazybytes.model.Customer;
import com.eazybytes.model.Role;
import com.eazybytes.repository.CustomerRepository;
import com.eazybytes.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final CustomerRepository customerRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<String> registerNewUser(@RequestBody Customer customer){
        try{
            String hashedPwd = passwordEncoder.encode(customer.getPwd());
            customer.setPwd(hashedPwd);

            //Default Configuration for any user logged in
            Role defaultRole = new Role();
            defaultRole.setCustomer(customer);
            defaultRole.setRole("ROLE_USER");

            Customer savedCustomer = customerRepository.save(customer);

            defaultRole.setCustomer(savedCustomer);
            Role savedRole = roleRepository.save(defaultRole);



             if(savedCustomer.getId() > 0){
                return ResponseEntity.status(HttpStatus.CREATED)
                        .body("Given user details are successfully registered");
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("User Register Failed");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An Exception Occured: "+e.getMessage());
        }
    }

    @GetMapping("/user")
    public Customer getUserDetailsAfterLogin(Authentication authentication){
        Customer customer = customerRepository.findByEmail(authentication.getName()).orElse(null);
        return customer;
    }
}
