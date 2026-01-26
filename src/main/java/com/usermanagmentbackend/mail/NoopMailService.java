package com.usermanagmentbackend.mail;

import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

@Service
@Primary
public class NoopMailService implements MailService {
	@Override
	public void sendPasswordReset(final String toEmail, final String link) {
		System.out.println("Mail disabled. Reset link for " + toEmail + ": " + link);
	}
}