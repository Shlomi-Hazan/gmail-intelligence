"""Narrow, read-only Gmail adapter. Exposes only what M1 needs; no message content."""
import json

PROFILE_FIELDS = ("emailAddress", "messagesTotal", "threadsTotal", "historyId")


class GmailApiError(Exception):
    """Gmail API problem. Messages never contain credentials or mailbox content."""


class GmailAuthError(GmailApiError):
    """401/403: credentials rejected or insufficient."""


class GmailRateLimitError(GmailApiError):
    """Rate limit still exceeded after retries."""


def _reasons(exc):
    """Error reason codes from the API error body (never includes request data)."""
    try:
        body = json.loads(exc.content.decode("utf-8", "replace"))
        return {e.get("reason") for e in body.get("error", {}).get("errors", [])}
    except (ValueError, AttributeError, TypeError):
        return set()


def _translate(exc):
    status = getattr(getattr(exc, "resp", None), "status", None)
    if status == 429 or (status == 403 and _reasons(exc) & {"rateLimitExceeded", "userRateLimitExceeded"}):
        return GmailRateLimitError("Gmail API rate limit exceeded; try again later")
    if status in (401, 403):
        return GmailAuthError(f"Gmail API rejected the credentials (HTTP {status}); run `auth login` again")
    return GmailApiError(f"Gmail API error (HTTP {status})")


class GmailReader:
    """Read-only operations: profile and label listing. Nothing else is exposed."""

    RETRIES = 3  # googleapiclient retries 429/5xx with exponential backoff

    def __init__(self, service):
        self._service = service

    def _execute(self, request):
        from googleapiclient.errors import HttpError

        try:
            return request.execute(num_retries=self.RETRIES)
        except HttpError as exc:
            raise _translate(exc) from None
        except OSError:
            raise GmailApiError("network error talking to the Gmail API") from None

    def get_profile(self):
        data = self._execute(self._service.users().getProfile(userId="me"))
        return {k: data.get(k) for k in PROFILE_FIELDS}

    def list_labels(self):
        data = self._execute(self._service.users().labels().list(userId="me"))
        return [{"id": x.get("id"), "type": x.get("type")} for x in data.get("labels", [])]


def build_reader(creds):
    from googleapiclient.discovery import build

    return GmailReader(build("gmail", "v1", credentials=creds, cache_discovery=False))
