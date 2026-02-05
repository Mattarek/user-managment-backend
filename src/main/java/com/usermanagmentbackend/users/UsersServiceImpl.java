package com.usermanagmentbackend.users;

import com.usermanagmentbackend.common.ApiException;
import com.usermanagmentbackend.domain.user.UserRepository;
import com.usermanagmentbackend.security.CurrentUser;
import com.usermanagmentbackend.users.dto.MeResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UsersServiceImpl implements UsersService {

	private final UserRepository userRepository;

	public UsersServiceImpl(
			final UserRepository userRepository
	) {
		this.userRepository = userRepository;
	}

	@Override
	@Transactional(readOnly = true)
	public MeResponse getMe() {
		final var auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || !(auth.getPrincipal() instanceof final CurrentUser currentUser)) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
		}

		final var user = userRepository.findByEmail(currentUser.email().toLowerCase())
				.orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"));

		return new MeResponse(user.getEmail(), user.getEmail(), user.getName(), user.getSurname());
	}
}