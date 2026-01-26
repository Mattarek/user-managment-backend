package com.usermanagmentbackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class UserManagmentBackendApplication {
	static void main(final String[] args) {
		SpringApplication.run(UserManagmentBackendApplication.class, args);
	}
}
