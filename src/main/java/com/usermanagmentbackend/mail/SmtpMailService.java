package com.usermanagmentbackend.mail;

import com.usermanagmentbackend.config.AppProperties;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

public class SmtpMailService implements MailService {
	private final JavaMailSender mailSender;
	private final AppProperties props;

	public SmtpMailService(final JavaMailSender mailSender, final AppProperties props) {
		this.mailSender = mailSender;
		this.props = props;
	}

	@Override
	public void sendPasswordReset(final String toEmail, final String link) {
		final MimeMessage message = mailSender.createMimeMessage();

		try {
			final MimeMessageHelper helper =
					new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, "UTF-8");

			helper.setFrom(props.mail().from());
			helper.setTo(toEmail);
			helper.setSubject("Reset your password");
			System.out.println("SENDING HTML RESET MAIL (v2) to=" + toEmail);

			final String text = """
					Reset your password
					
					We received a request to reset the password for your account.
					Use the link below to choose a new password:
					
					%s
					
					If you didn’t request a password reset, you can safely ignore this email.
					""".formatted(link);

			final String html = PasswordResetTemplate.html(
					"DoctorsApp",
					link
			);

			helper.setText(text, html);

			mailSender.send(message);
		} catch (final MessagingException e) {
			throw new MailSendException("Failed to send password reset email to " + toEmail, e);
		}
	}
}