package com.usermanagmentbackend.mail;

public interface MailService {
	void sendPasswordReset(String toEmail, String link);
}