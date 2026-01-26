package com.usermanagmentbackend.mail;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(prefix = "app.mail", name = "enabled", havingValue = "false", matchIfMissing = true)
public class NoopMailService implements MailService {
	@Override
	public void sendPasswordReset(final String toEmail, final String link) {
		System.out.println("Mail disabled. Reset link for " + toEmail + ": " + link);
	}
}