package com.usermanagmentbackend.users;

import com.usermanagmentbackend.users.dto.MeResponse;

public interface UsersService {
	MeResponse getMe();

	void remindPassword(String email);
}