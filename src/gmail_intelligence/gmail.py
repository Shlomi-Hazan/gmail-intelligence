"""Narrow, read-only Gmail adapter. No message bodies, snippets, attachments or write operations."""
import json
from email.utils import parseaddr

PROFILE_FIELDS = ("emailAddress", "messagesTotal", "threadsTotal", "historyId")


class GmailApiError(Exception):
    """Gmail API problem. Messages never contain credentials or mailbox content."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status  # HTTP status, or None for network-level errors


class GmailNotFoundError(GmailApiError):
    """404: the message no longer exists."""


class GmailHistoryNotFoundError(GmailNotFoundError):
    """404 from history.list: the startHistoryId (or page token) is out of the available range or unknown."""


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
        return GmailRateLimitError("Gmail API rate limit exceeded; try again later", status)
    if status in (401, 403):
        return GmailAuthError(f"Gmail API rejected the credentials (HTTP {status}); run `auth login` again", status)
    if status == 404:
        return GmailNotFoundError("Gmail resource not found (HTTP 404)", 404)
    return GmailApiError(f"Gmail API error (HTTP {status})", status)


class GmailReader:
    """Read-only operations. Nothing that writes, sends, trashes or deletes is exposed."""

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


    def list_label_details(self):
        data = self._execute(self._service.users().labels().list(
            userId="me", fields="labels/id,labels/name,labels/type"))
        return [{"id": x.get("id"), "name": x.get("name"), "type": x.get("type")} for x in data.get("labels", [])]

    def list_message_ids(self, page_token=None, max_results=500):
        """One page of message ids (spam/trash included), newest first. Returns (ids, next_page_token)."""
        data = self._execute(self._service.users().messages().list(
            userId="me", maxResults=max_results, pageToken=page_token, includeSpamTrash=True,
            fields="messages/id,nextPageToken"))
        return [m["id"] for m in data.get("messages", []) if m.get("id")], data.get("nextPageToken")

    HISTORY_TYPES = ["messageAdded", "messageDeleted", "labelAdded", "labelRemoved"]

    def list_history(self, start_history_id, page_token=None, max_results=100):
        """One page of mailbox change records after `start_history_id` (ids only; gmail.readonly). M7A.

        Returns {"records": [{"id", "added", "deleted", "labels"}], "next": token or None, "history_id": current mailbox id or None}.
        The message lists hold message ids only. A 404 raises GmailHistoryNotFoundError (expired or unknown id / token).
        """
        from googleapiclient.errors import HttpError

        try:
            data = self._service.users().history().list(
                userId="me", startHistoryId=str(start_history_id), pageToken=page_token, maxResults=max_results, historyTypes=self.HISTORY_TYPES,
                fields="history(id,messagesAdded/message/id,messagesDeleted/message/id,labelsAdded/message/id,labelsRemoved/message/id),nextPageToken,historyId"
            ).execute(num_retries=self.RETRIES)
        except HttpError as exc:
            err = _translate(exc)
            if isinstance(err, GmailNotFoundError):
                raise GmailHistoryNotFoundError("Gmail history not found (HTTP 404)", 404) from None
            raise err from None
        except OSError:
            raise GmailApiError("network error talking to the Gmail API") from None
        records = []
        for rec in data.get("history") or []:
            def ids(key):
                return [m["message"]["id"] for m in rec.get(key) or [] if isinstance(m, dict) and isinstance(m.get("message"), dict)
                        and isinstance(m["message"].get("id"), str)]
            records.append({"id": str(rec.get("id")), "added": ids("messagesAdded"), "deleted": ids("messagesDeleted"),
                            "labels": ids("labelsAdded") + ids("labelsRemoved")})
        hid = data.get("historyId")
        return {"records": records, "next": data.get("nextPageToken"), "history_id": None if hid is None else str(hid)}

    def get_message_metadata(self, message_id):
        """Metadata only: ids, date, size, label ids and the From address. No snippet, body or attachments."""
        data = self._execute(self._service.users().messages().get(
            userId="me", id=message_id, format="metadata", metadataHeaders=["From"],
            fields="id,threadId,internalDate,labelIds,sizeEstimate,payload/headers"))
        if not data.get("id"):
            raise GmailApiError("malformed Gmail response (no message id)")
        sender = None
        for h in (data.get("payload") or {}).get("headers") or []:
            if str(h.get("name", "")).lower() == "from":
                addr = parseaddr(str(h.get("value", "")))[1].strip().lower()
                sender = addr or None
                break
        return {"id": data["id"], "thread_id": data.get("threadId"),
                "internal_ms": _to_int(data.get("internalDate")), "size": _to_int(data.get("sizeEstimate")),
                "sender": sender, "label_ids": [x for x in data.get("labelIds") or [] if isinstance(x, str)]}


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_reader(creds):
    from googleapiclient.discovery import build

    return GmailReader(build("gmail", "v1", credentials=creds, cache_discovery=False))
