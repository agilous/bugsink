from smtplib import SMTPAuthenticationError
from unittest import TestCase as RegularTestCase
from unittest.mock import patch

from django.core.mail import send_mail
from django.test import SimpleTestCase, override_settings

from .email_backends import xoauth2_authobject


class XOAuth2AuthObjectTestCase(RegularTestCase):

    def test_initial_response_carries_user_and_token(self):
        authobject = xoauth2_authobject("bugsink@example.org", "TOKEN")
        self.assertEqual("user=bugsink@example.org\x01auth=Bearer TOKEN\x01\x01", authobject())

    def test_challenge_after_rejected_token_gets_empty_response(self):
        authobject = xoauth2_authobject("bugsink@example.org", "TOKEN")
        self.assertEqual("", authobject(b'{"status":"401"}'))


@override_settings(
    EMAIL_BACKEND="bugsink.email_backends.OAuth2EmailBackend",
    EMAIL_HOST="smtp.example.org",
    EMAIL_HOST_USER="bugsink@example.org",
    EMAIL_HOST_PASSWORD="not-used",
    EMAIL_USE_TLS=True,
    EMAIL_OAUTH2_TOKEN_URL="https://login.example.org/tenant/oauth2/v2.0/token",
    EMAIL_OAUTH2_CLIENT_ID="client-id",
    EMAIL_OAUTH2_CLIENT_SECRET="client-secret",
    EMAIL_OAUTH2_SCOPE="https://outlook.example.org/.default",
)
@patch("bugsink.email_backends.requests.post")
@patch("django.core.mail.backends.smtp.smtplib.SMTP")
class OAuth2EmailBackendTestCase(SimpleTestCase):

    def test_sends_mail_authenticated_with_token_instead_of_password(self, smtp_class, post):
        post.return_value.json.return_value = {"access_token": "TOKEN"}
        smtp = smtp_class.return_value
        smtp.sendmail.return_value = {}

        send_mail("Subject", "Body", "bugsink@example.org", ["user@example.com"])

        self.assertEqual("https://login.example.org/tenant/oauth2/v2.0/token", post.call_args.args[0])
        self.assertEqual({
            "grant_type": "client_credentials",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "scope": "https://outlook.example.org/.default",
        }, post.call_args.kwargs["data"])

        smtp.starttls.assert_called_once()
        smtp.login.assert_not_called()
        mechanism, authobject = smtp.auth.call_args.args
        self.assertEqual("XOAUTH2", mechanism)
        self.assertEqual("user=bugsink@example.org\x01auth=Bearer TOKEN\x01\x01", authobject())
        smtp.sendmail.assert_called_once()

    def test_rejected_token_closes_connection_and_raises(self, smtp_class, post):
        post.return_value.json.return_value = {"access_token": "TOKEN"}
        smtp = smtp_class.return_value
        smtp.auth.side_effect = SMTPAuthenticationError(535, b"5.7.3 Authentication unsuccessful")

        with self.assertRaises(SMTPAuthenticationError):
            send_mail("Subject", "Body", "bugsink@example.org", ["user@example.com"])

        smtp.quit.assert_called_once()
        smtp.sendmail.assert_not_called()
