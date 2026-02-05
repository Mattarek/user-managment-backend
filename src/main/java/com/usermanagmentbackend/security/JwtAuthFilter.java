package com.usermanagmentbackend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
	private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
	private final JwtService jwtService;

	public JwtAuthFilter(final JwtService jwtService) {
		this.jwtService = jwtService;
	}

	@Override
	protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
			throws ServletException, IOException {

		final String auth = request.getHeader("Authorization");
		if (auth != null && auth.startsWith("Bearer ")) {
			final String token = auth.substring(7);
			final CurrentUser cu = jwtService.parseAccessToken(token);

			log.debug("REQ {} {} AuthorizationHeader={}", request.getMethod(), request.getRequestURI(), auth);

			if (cu != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				final var principal = cu;
				final var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
				final var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}

		chain.doFilter(request, response);
	}
}

