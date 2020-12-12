# Spring-security-jwt-tutorial

## Spring-security-jwt-tutorial is an example of Spring Boot Application for Securing a REST API with JWT (JSON Web Token).

We will see how to secure rest API through JWT token in basic way.

## Setup project

**Modules used for Application**

* JAVA 8
* Spring boot
* h2-database

**Dependency**

* Spring Web
* Data JPA
* H2-Database
* Spring Security
* JWT
* Devtool

**Enable Spring Security for Spring boot App**

As we know by adding Spring security dependency by default Spring gives us a login page and working as protecting our App. But there has some issue, that is username of the loging page is by default **user** and password will be generate on console page like given below.

	Using generated security password: 937e8fe0-cff5-4b1c-bc00-59c3c44d6c2a

You can customize the **Username** and **password** from **application.properties** which is given below :

	spring.security.user.name= vikash
	spring.security.user.password= pass
	
Before start JWT token implementation we will see quick review on http basic authentication using Spring Security.

## Http Basic Authentication

**WebSecurityConfigurerAdapter**

We can either implements the interface called WebSecurityConfigurer or extend the more convenient class called WebSecurityConfigurerAdapter. The advantage of extending the adapter class is that we can configure Web security by overriding only those parts that we are interested in; others can remain their default form.

	// The annotation @EnableWebSecurity enables Web security; otherwise, it remains disabled by default.
	@Configuration
	@EnableWebSecurity
	public class SecurityConfig extends WebSecurityConfigurerAdapter {
	}

We need to override configure(AuthenticationManagerBuilder auth) method to customize or validate user details before handle to the spring to login it.

	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService);
	}
	
For password Encoding we need to create the bean of PasswordEncoder.

	@Bean
	public PasswordEncoder passwordEncoder() {
		// If you don't want to use BCrypt password you can use NoOpPasswordEncoder but it is deprecated :
		return NoOpPasswordEncoder.getInstance()
	}
	
To Authenticate the user we need to implement UserDetailsService interface.

	@Service
	public class CustomUserDetailsService implements UserDetailsService {
	
		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			return new User("vikash", "pass", new ArrayList<>());
		}
	}
