package com.usermanagmentbackend.mail;

public class NoopMailService implements MailService {
	@Override
	public void sendPasswordReset(final String toEmail, final String link) {
		System.out.println("Mail disabled. Reset link for " + toEmail + ": " + link);
	}
}