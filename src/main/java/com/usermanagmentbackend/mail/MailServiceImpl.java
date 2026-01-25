package com.usermanagmentbackend.mail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailServiceImpl implements MailService {
	private static final Logger log = LoggerFactory.getLogger(MailServiceImpl.class);

	private final JavaMailSender mailSender;

	public MailServiceImpl(final JavaMailSender mailSender) {
		this.mailSender = mailSender;
	}

	@Override
	public void sendPasswordReset(final String toEmail, final String link) {
		// Jeśli SMTP nie jest ustawione, i tak zobaczysz błąd w logach — w dev możesz po prostu logować link.
		try {
			final var msg = new SimpleMailMessage();
			msg.setTo(toEmail);
			msg.setSubject("Password reset");
			msg.setText("Reset your password using the link: " + link);
			mailSender.send(msg);
		} catch (final Exception e) {
			log.warn("Could not send email via SMTP. Link (DEV fallback): {}", link);
		}
	}
}