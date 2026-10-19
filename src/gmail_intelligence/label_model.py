"""Label model shared by the M5 features (hygiene, recommendations, filter suggestions, label-change plans). Pure and local: NO Gmail, no OAuth, no Keychain, no network.

A Gmail label is identified by an opaque id and has a display name; nesting is expressed ONLY through the name (`Parent/Child`). System labels (INBOX, SENT, the CATEGORY_*
tabs, ...) are never the subject of any M5 finding, recommendation or plan. Label NAMES are private user content: everything here returns them as data and leaves display
decisions (hidden by default) to the report modules.

Normalization rules (small and documented; deliberately not aggressive, so a "duplicate" warning is rarely misleading):
  * `normalize`       : Unicode NFKC, case-fold, trim each path segment and collapse inner whitespace. Two names that are equal after this differ only in case, spacing or
                        Unicode compatibility form.
  * `normalize_loose` : additionally treats `-`, `_` and `.` as spaces. Equal only after this step means the names differ in punctuation as well.
  Accents, plurals and word order are never normalized away (a bounded edit distance reports near-misses at LOW confidence instead).
"""
import re
import unicodedata

MAX_DEPTH = 3  # the recommended maximum nesting depth (segments); deeper labels are reported and never created by a plan
MAX_NAME_LEN = 225  # conservative local limit for a full label path
MAX_SEGMENT_LEN = 100
NEAR_MIN_LEN = 5  # shortest leaf name compared with an edit distance (short names produce noise)
NEAR_MAX_DISTANCE = 1

SYSTEM_IDS = frozenset({"INBOX", "UNREAD", "IMPORTANT", "STARRED", "SENT", "DRAFT", "SPAM", "TRASH", "CHAT", "YELLOW_STAR", "BLUE_STAR", "RED_STAR",
                        "ORANGE_STAR", "GREEN_STAR", "PURPLE_STAR", "YELLOW_BANG", "RED_BANG", "BLUE_INFO", "GREEN_CHECK", "ORANGE_GUILLEMET",
                        "PURPLE_QUESTION"})
# Names a label created or renamed by a PLAN may never take (case-insensitive), because Gmail uses them for system labels. They are not an inventory finding: an existing
# user label that happens to carry such a name is not reported as a problem.
RESERVED_NAMES = frozenset(n.casefold() for n in (
    "INBOX", "UNREAD", "IMPORTANT", "STARRED", "SENT", "SENT MAIL", "DRAFT", "DRAFTS", "SPAM", "TRASH", "CHAT", "CHATS", "ALL MAIL",
    "CATEGORY_PERSONAL", "CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS", "CATEGORY_UPDATES", "CATEGORY_FORUMS"))
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SPACES = re.compile(r"\s+")
_LOOSE = re.compile(r"[-_.]+")


class Label:
    """One label of the local inventory. `type` is Gmail's own 'system' or 'user' (None when the inventory predates it)."""
    __slots__ = ("id", "name", "type")

    def __init__(self, id, name, type=None):
        self.id, self.name, self.type = id, name or "", type

    def __repr__(self):
        return "<Label>"  # never prints a private name

    @property
    def system(self):
        return self.type == "system" or self.id in SYSTEM_IDS or self.id.startswith("CATEGORY_")

    @property
    def user(self):
        return not self.system and (self.type == "user" or self.id.startswith("Label_"))


def load_labels(index, account):
    """The account's labels from the local inventory, sorted by id (deterministic)."""
    return [Label(r["id"], r["name"], r["type"]) for r in index._q("SELECT id, name, type FROM labels WHERE account=? ORDER BY id", account)]


def message_counts(index, account):
    """{label id: number of indexed messages that carry it}. Only messages that exist in the local index count."""
    return {r["label_id"]: r["n"] for r in index._q(
        "SELECT ml.label_id, COUNT(*) n FROM message_labels ml JOIN messages m ON m.account=ml.account AND m.id=ml.message_id "
        "WHERE ml.account=? GROUP BY ml.label_id ORDER BY ml.label_id", account)}


def segments(name):
    return name.split("/")


def depth(name):
    return len(segments(name))


def leaf(name):
    return segments(name)[-1]


def parent_path(name):
    segs = segments(name)
    return "/".join(segs[:-1])


def normalize(name):
    """NFKC, case-fold, trim each segment and collapse inner whitespace. See the module docstring."""
    text = unicodedata.normalize("NFKC", name or "")
    return "/".join(_SPACES.sub(" ", seg.strip()).casefold() for seg in text.split("/"))


def normalize_loose(name):
    """`normalize` plus `-`, `_` and `.` treated as spaces."""
    return "/".join(_SPACES.sub(" ", _LOOSE.sub(" ", seg)).strip() for seg in normalize(name).split("/"))


def name_problem(name):
    """None for a usable label path, else a short code. Applies to names a plan would create or rename to, and to the inventory check."""
    if not isinstance(name, str) or not name or not name.strip():
        return "EMPTY_NAME"
    if name != unicodedata.normalize("NFC", name):
        return "NOT_NFC"
    if _CONTROL.search(name):
        return "CONTROL_CHARACTER"
    if name != name.strip():
        return "OUTER_SPACE"
    if len(name) > MAX_NAME_LEN:
        return "TOO_LONG"
    segs = segments(name)
    if any(not s.strip() for s in segs):
        return "EMPTY_SEGMENT"
    if any(s != s.strip() for s in segs):
        return "SEGMENT_SPACE"
    if any(len(s) > MAX_SEGMENT_LEN for s in segs):
        return "SEGMENT_TOO_LONG"
    return None


def reserved(name):
    """True for a path that would collide with a system label's name or id (checked on the top-level segment and on the whole name). Used by plans only."""
    top = normalize(segments(name)[0]) if name else ""
    system = {i.casefold() for i in SYSTEM_IDS}
    return top in RESERVED_NAMES or top in system or top.startswith("category_") or normalize(name) in RESERVED_NAMES


def edit_distance_within(a, b, limit=NEAR_MAX_DISTANCE):
    """True if the Damerau-Levenshtein (adjacent transposition) distance between a and b is at most `limit`. Bounded and deterministic."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > limit:
        return False
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return False
        prev2, prev = prev, cur
    return prev[-1] <= limit
