package com.usermanagmentbackend.mail;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
public class MailConfiguration {

	@Bean
	@ConditionalOnProperty(prefix = "spring.mail", name = "host")
	MailService smtpMailService(final JavaMailSender sender) {
		return new MailServiceImpl(sender);
	}

	@Bean
	@ConditionalOnMissingBean(MailService.class)
	MailService noopMailService() {
		return (to, link) -> System.out.println("Mail not configured. Reset link for " + to + ": " + link);
	}
}