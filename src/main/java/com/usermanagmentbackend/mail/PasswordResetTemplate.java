package com.usermanagmentbackend.mail;

import java.time.Year;

public class PasswordResetTemplate {

	private PasswordResetTemplate() {
	}

	public static String html(final String appName, final String resetLink) {
		return """
				<!doctype html>
				<html lang="en">
				<head>
				  <meta charset="utf-8" />
				  <meta name="viewport" content="width=device-width,initial-scale=1" />
				  <title>Reset your password</title>
				</head>
				<body style="margin:0;padding:0;background:#f5f7fb;font-family:Arial,Helvetica,sans-serif;">
				  <table width="100%%" cellpadding="0" cellspacing="0" style="background:#f5f7fb;padding:24px;">
				    <tr>
				      <td align="center">
				        <table width="600" cellpadding="0" cellspacing="0"
				               style="background:#ffffff;border-radius:16px;padding:24px;">
				          <tr>
				            <td>
				              <h2 style="margin:0 0 16px;">Reset your password</h2>
				              <p>
				                We received a request to reset the password for your %s account.
				              </p>
				              <p style="margin:24px 0;">
				                <a href="%s"
				                   style="display:inline-block;padding:12px 20px;
				                          background:#2563eb;color:#ffffff;
				                          text-decoration:none;border-radius:8px;
				                          font-weight:bold;">
				                  Reset password
				                </a>
				              </p>
				              <p style="color:#555;font-size:14px;">
				                If you didn’t request a password reset, you can safely ignore this email.
				              </p>
				              <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;">
				              <p style="font-size:12px;color:#777;">
				                © %d %s
				              </p>
				            </td>
				          </tr>
				        </table>
				      </td>
				    </tr>
				  </table>
				</body>
				</html>
				""".formatted(appName, resetLink, Year.now().getValue(), appName);
	}
}
