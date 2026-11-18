import re
import requests

from django.conf import settings
from django.core.mail.backends.console import EmailBackend as ConsoleEmailBackend
from django.core.mail.backends.smtp import EmailBackend as SMTPEmailBackend


class QuietConsoleEmailBackend(ConsoleEmailBackend):

    def write_message(self, message):
        msg = message.message()
        # self.stream.write("From: %s\n" % msg["From"])
        # self.stream.write("To: %s\n" % msg["To"])
        subject_header = msg["Subject"]

        # Headers may contain newlines, RFC 2822 section 2.2.3 says:
        #
        # > The process of moving from this folded multiple-line representation
        # > of a header field to its single line representation is called
        # > "unfolding". Unfolding is accomplished by simply removing any CRLF
        # > that is immediately followed by WSP. Each header field should be
        # > treated in its unfolded form for further syntactic and semantic
        # > evaluation.
        #
        # Remove those with a simple regex
        # the regex says: match newline followed by whitespace, replace with just the matched whitespace:
        subject = re.sub(r"\n(\s+)", (r"\1"), subject_header)
        self.stream.write("Email is not set up, the following was not sent: %s\n" % subject)


def xoauth2_authobject(username, access_token):
    # smtplib asks for the initial response without a challenge. A challenge only comes back when the token is
    # rejected, and must be answered with an empty response to get the server's actual error.
    def authobject(challenge=None):
        if challenge is None:
            return f"user={username}\x01auth=Bearer {access_token}\x01\x01"
        return ""

    return authobject


class OAuth2EmailBackend(SMTPEmailBackend):
    """SMTP, authenticated with an OAuth2 access token (SASL XOAUTH2) instead of a password.

    The token comes from the OAuth2 client credentials grant, which is how Microsoft 365 lets an application (rather
    than a person) send email over SMTP once basic auth is gone.
    """

    def fetch_access_token(self):
        response = requests.post(settings.EMAIL_OAUTH2_TOKEN_URL, data={
            "grant_type": "client_credentials",
            "client_id": settings.EMAIL_OAUTH2_CLIENT_ID,
            "client_secret": settings.EMAIL_OAUTH2_CLIENT_SECRET,
            "scope": settings.EMAIL_OAUTH2_SCOPE,
        }, timeout=self.timeout)
        response.raise_for_status()
        return response.json()["access_token"]

    def open(self):
        self.password = None  # keeps super().open() from logging in with a password; we authenticate below
        opened = super().open()
        if opened:
            try:
                self.connection.ehlo_or_helo_if_needed()
                self.connection.auth("XOAUTH2", xoauth2_authobject(self.username, self.fetch_access_token()))
            except OSError:
                self.close()
                if not self.fail_silently:
                    raise
                return None
        return opened
