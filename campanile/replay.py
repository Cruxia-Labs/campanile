"""The custody replay — PHYSICS_CLAIMS.md §4 made executable.

Streams `git log -p` over the first-parent chain (root→HEAD) and maintains,
per file, WHO owns each surviving line (text) or the whole file (binary).
Only hunk headers are read for attribution — content lines are consumed by
count and never inspected, so custody is pure arithmetic over the recorded
diffs. Attribution is the commit author string, verbatim (§4.2); merges diff
against the first parent and attribute to the merge author (§4.3).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

# Field/record separators for the log format; \x01 opens a commit header so
# it can never be confused with diff text.
_REC = "\x01"
_SEP = "\x1f"

# Environment pins so a user's git config can't change the record (§6 V3).
GIT_PINS = [
    "-c", "core.quotepath=false",
    "-c", "core.autocrlf=false",
    "-c", "diff.algorithm=myers",
    "-c", "diff.noprefix=false",
    "-c", "diff.external=",
    "-c", "diff.renameLimit=0",
]

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_BINARY_RE = re.compile(r"^Binary files (?:a/(.*)|/dev/null) and (?:b/(.*)|/dev/null) differ$")


def _git(repo: str, *args: str) -> str:
    out = subprocess.run(
        ["git", *GIT_PINS, "-C", repo, *args],
        check=True, capture_output=True,
    )
    return out.stdout.decode("utf-8", errors="surrogateescape")


@dataclass
class Commit:
    sha: str
    author: str
    date: str  # committer date, ISO-8601, as recorded


@dataclass
class CustodyState:
    """text: path -> list of author ids (one per line); binary: path -> author id."""

    text: dict[str, list[int]] = field(default_factory=dict)
    binary: dict[str, int] = field(default_factory=dict)
    authors: list[str] = field(default_factory=list)
    _author_ids: dict[str, int] = field(default_factory=dict)
    # every author who ever landed a diff on the path (rename-following), §5 M5
    ever_authors: dict[str, set[int]] = field(default_factory=dict)

    def author_id(self, name: str) -> int:
        aid = self._author_ids.get(name)
        if aid is None:
            aid = len(self.authors)
            self.authors.append(name)
            self._author_ids[name] = aid
        return aid


@dataclass
class _FileDiff:
    old_path: str | None = None
    new_path: str | None = None
    rename_from: str | None = None
    rename_to: str | None = None
    is_binary: bool = False
    # hunks as (old_start, old_count, new_count)
    hunks: list[tuple[int, int, int]] = field(default_factory=list)


def first_parent_chain(repo: str, pin: str) -> list[str]:
    return _git(repo, "rev-list", "--first-parent", "--reverse", pin).split()


def merge_shas(repo: str, pin: str) -> list[str]:
    return _git(repo, "rev-list", "--first-parent", "--merges", pin).split()


def _apply_file_diff(state: CustodyState, fd: _FileDiff, aid: int) -> None:
    old = fd.rename_from if fd.rename_from is not None else fd.old_path
    new = fd.rename_to if fd.rename_to is not None else fd.new_path

    # a rename moves custody and the ever-author set with the file
    if old is not None and new is not None and old != new:
        if old in state.text:
            state.text[new] = state.text.pop(old)
        if old in state.binary:
            state.binary[new] = state.binary.pop(old)
        if old in state.ever_authors:
            state.ever_authors[new] = state.ever_authors.pop(old)

    target = new if new is not None else old
    if target is None:
        return
    state.ever_authors.setdefault(target, set()).add(aid)

    if fd.is_binary:
        if new is None:  # deleted binary
            state.binary.pop(old, None)
            state.ever_authors.pop(old, None)
        else:
            state.text.pop(target, None)  # text->binary type change
            state.binary[target] = aid
        return

    if new is None:  # deleted text file
        state.text.pop(old, None)
        state.ever_authors.pop(old, None)
        return

    if not fd.hunks:
        # pure rename or mode-only change: no content delta, so custody is
        # whatever it already was — a binary file MUST stay binary (a pure
        # rename of a binary emits no "Binary files" marker, so is_binary is
        # False here and falling through would corrupt its custody); only a
        # genuinely new empty file gains an (empty) text entry
        if target not in state.text and target not in state.binary:
            state.text[target] = []
        return

    lines = state.text.get(target)
    if lines is None:
        state.binary.pop(target, None)  # binary->text type change
        lines = []
    offset = 0
    for old_start, old_count, new_count in fd.hunks:
        if old_count > 0:
            start = old_start - 1 + offset
            lines[start : start + old_count] = [aid] * new_count
        else:
            # unified-diff convention: zero old_count inserts AFTER old_start
            start = old_start + offset
            lines[start:start] = [aid] * new_count
        offset += new_count - old_count
    state.text[target] = lines


def _strip_prefix(path: str, prefix: str) -> str:
    return path[2:] if path.startswith(prefix) else path


def replay(repo: str, pin: str, on_commit) -> CustodyState:
    """Stream the chain; after applying each commit, call on_commit(index, commit,
    touched_paths, state). Returns the final state."""
    proc = subprocess.Popen(
        [
            "git", *GIT_PINS, "-C", repo, "log", "--first-parent", "--reverse",
            "-p", "-M", "--unified=0", "--no-color", "--no-ext-diff",
            f"--format={_REC}%H{_SEP}%an{_SEP}%cI", pin,
        ],
        stdout=subprocess.PIPE,
    )
    assert proc.stdout is not None
    state = replay_from_lines(proc.stdout, on_commit)
    ret = proc.wait()
    if ret != 0:
        raise RuntimeError(f"git log exited {ret}")
    return state


def replay_from_lines(byte_lines, on_commit,
                      structural_only: bool = False) -> CustodyState:
    """The frozen parse loop, fed by any iterable of raw byte lines.

    THE SEAM (Campanile WS2): `replay()` feeds it live `git log -p`
    stdout; the shipped fixture feeds it the recorded STRUCTURAL byte
    stream. With structural_only=True the hunk content lines are absent
    from the stream, so the skip counter is never armed — that one
    guarded line is the entire behavioural delta of the re-host.
    """
    state = CustodyState()

    index = -1
    commit: Commit | None = None
    aid = -1
    fd: _FileDiff | None = None
    touched: list[str] = []
    skip = 0  # content lines still to consume for the current hunk

    def flush_file() -> None:
        nonlocal fd
        if fd is not None:
            _apply_file_diff(state, fd, aid)
            # both names of a rename are "touched": consumers must be able to
            # see that the old path no longer exists in the state
            t_old = fd.rename_from if fd.rename_from is not None else fd.old_path
            t_new = fd.rename_to if fd.rename_to is not None else fd.new_path
            for t in (t_old, t_new):
                if t is not None and t not in touched:
                    touched.append(t)
            fd = None

    def flush_commit() -> None:
        nonlocal touched
        flush_file()
        if commit is not None:
            on_commit(index, commit, touched, state)
        touched = []

    for raw in byte_lines:
        line = raw.decode("utf-8", errors="surrogateescape").rstrip("\n")
        if skip > 0:
            if not line.startswith("\\"):
                skip -= 1
            continue
        if line.startswith(_REC):
            flush_commit()
            sha, author, date = line[1:].split(_SEP)
            index += 1
            commit = Commit(sha, author, date)
            aid = state.author_id(author)
            continue
        if commit is None:
            continue
        if line.startswith("diff --git "):
            flush_file()
            fd = _FileDiff()
            continue
        if fd is None:
            continue
        m = _HUNK_RE.match(line)
        if m:
            old_start = int(m.group(1))
            old_count = 1 if m.group(2) is None else int(m.group(2))
            new_count = 1 if m.group(4) is None else int(m.group(4))
            fd.hunks.append((old_start, old_count, new_count))
            skip = 0 if structural_only else old_count + new_count
            continue
        if line.startswith("rename from "):
            fd.rename_from = line[len("rename from "):]
        elif line.startswith("rename to "):
            fd.rename_to = line[len("rename to "):]
        elif line.startswith("--- "):
            p = line[4:]
            fd.old_path = None if p == "/dev/null" else _strip_prefix(p, "a/")
        elif line.startswith("+++ "):
            p = line[4:]
            fd.new_path = None if p == "/dev/null" else _strip_prefix(p, "b/")
        else:
            m = _BINARY_RE.match(line)
            if m:
                fd.is_binary = True
                fd.old_path = m.group(1)
                fd.new_path = m.group(2)

    flush_commit()
    return state
