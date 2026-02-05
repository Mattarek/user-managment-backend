package com.usermanagmentbackend.users;

import com.usermanagmentbackend.users.dto.MeResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UsersController {

	private final UsersService usersService;

	public UsersController(final UsersService usersService) {
		this.usersService = usersService;
	}

	@GetMapping("/getMe")
	public MeResponse getMe() {
		return usersService.getMe();
	}
}