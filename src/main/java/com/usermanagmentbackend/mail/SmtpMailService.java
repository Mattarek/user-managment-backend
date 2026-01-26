package com.usermanagmentbackend.mail;

import com.usermanagmentbackend.config.AppProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@ConditionalOnProperty(prefix = "app.mail", name = "enabled", havingValue = "true")
public class SmtpMailService implements MailService {

	private final JavaMailSender mailSender;
	private final AppProperties props;

	public SmtpMailService(final JavaMailSender mailSender,
						   final AppProperties props) {
		this.mailSender = mailSender;
		this.props = props;
	}

	@Override
	public void sendPasswordReset(final String toEmail, final String link) {
		final SimpleMailMessage msg = new SimpleMailMessage();
		msg.setFrom(props.mail().from());
		msg.setTo(toEmail);
		msg.setSubject("Reset hasła");
		msg.setText("Kliknij link:\n" + link);

		mailSender.send(msg);
	}
}