package com.usermanagmentbackend.mail;

import com.usermanagmentbackend.config.AppProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
public class MailConfiguration {

	public MailConfiguration(final Environment env) {
		System.out.println("app.mail.enabled = " + env.getProperty("app.mail.enabled"));
		System.out.println("MAIL_ENABLED = " + env.getProperty("MAIL_ENABLED"));
	}

	@Bean
	@ConditionalOnProperty(prefix = "app.mail", name = "enabled", havingValue = "true")
	public MailService smtpMailService(final JavaMailSender sender, final AppProperties props) {
		return new SmtpMailService(sender, props);
	}

	@Bean
	@ConditionalOnProperty(prefix = "app.mail", name = "enabled", havingValue = "false", matchIfMissing = true)
	public MailService noopMailService() {
		return new NoopMailService();
	}
}