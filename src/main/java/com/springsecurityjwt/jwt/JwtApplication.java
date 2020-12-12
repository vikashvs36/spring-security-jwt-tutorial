package com.springsecurityjwt.jwt;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.springsecurityjwt.jwt.dao.UserRepository;
import com.springsecurityjwt.jwt.entity.User;

@SpringBootApplication
public class JwtApplication {

	@Autowired
	private UserRepository userRepository; 
	
	@PostConstruct
	public void init() {
		List<User> users = Stream.of(new User("vikash", "singh", "vikash@gmail.com"),
				new User("user1", "pass1", "user1@gmail.com"), new User("user2", "pass2", "user2@gmail.com"),
				new User("user3", "pass3", "user3@gmail.com"), new User("user4", "pass4", "user4@gmail.com"))
				.collect(Collectors.toList());
		userRepository.saveAll(users);
	}
	
	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

}
