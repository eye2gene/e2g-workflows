"""Make CI accept the quarantine exceptions a project's ``uv.lock`` records, if the shared list allows them.

Every Eye2Gene project locks with ``exclude-newer = "7 days"``. A security fix younger than that is admitted through
``quarantine-exceptions.toml`` in this repository (added with ``just allow <package>`` from any project), and uv
records each exception it used under ``[options.exclude-newer-package]`` of the project's ``uv.lock``. ``uv sync``
under ``UV_LOCKED=1`` then refuses the lock unless the same exceptions are in its configuration, so this script:

1. writes the lock's own exceptions to the runner's user-level uv configuration, which every ``uv`` command reads;
2. fails the job when the lock lets a package in, today, that the shared list does not allow;
3. annotates the active exceptions and warns about expired ones, listed or not: by then they only pin their
   package, since the global rule admits everything they admit, until the project's next ``just up``.

Usage: ``python3 uv_quarantine_ci.py <uv.lock> <quarantine-exceptions.toml>``. Standard library only (3.11+).
"""

import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import tomllib

LIST_REPO = "eye2Gene/e2g-workflows"
TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"
BLOCK_BEGIN = (
    "# >>> e2g quarantine exceptions (managed: edit eye2Gene/e2g-workflows instead) >>>"
)
BLOCK_END = "# <<< e2g quarantine exceptions <<<"
_BLOCK = re.compile(
    rf"^{re.escape(BLOCK_BEGIN)}\n.*?^{re.escape(BLOCK_END)}\n?",
    re.MULTILINE | re.DOTALL,
)


def normalize(name: str) -> str:
    """Return a package name as uv writes it: lower case, runs of ``-``, ``_`` and ``.`` as one ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_timestamp(value: object, *, what: str) -> datetime:
    """Return an ISO 8601 string or a TOML date-time as an aware UTC time."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SystemExit(f"{what}: {value!r} is not an ISO 8601 timestamp") from exc
    else:
        raise SystemExit(f"{what}: {value!r} is not a timestamp")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_timestamp(moment: datetime) -> str:
    """Return ``moment`` the way uv writes it in ``uv.lock``."""
    return moment.astimezone(UTC).strftime(TIMESTAMP)


def lock_exceptions(lock_text: str) -> dict[str, datetime | None]:
    """Return the exceptions uv recorded: package to cutoff, or None where it is not quarantined at all."""
    options = tomllib.loads(lock_text).get("options")
    table = options.get("exclude-newer-package") if isinstance(options, dict) else None
    if not isinstance(table, dict):
        return {}
    return {
        normalize(name): None
        if value is False
        else parse_timestamp(value, what=f"uv.lock {name}")
        for name, value in table.items()
    }


def load_list(text: str) -> tuple[int, frozenset[str], list[tuple[str, datetime, str]]]:
    """Return the quarantine length, the packages that never wait, and (package, cutoff, description) per entry."""
    data = tomllib.loads(text)
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise SystemExit("quarantine-exceptions.toml: missing [policy]")
    days = policy.get("quarantine-days")
    if not isinstance(days, int) or days <= 0:
        raise SystemExit(
            "quarantine-exceptions.toml: [policy] quarantine-days must be a positive integer"
        )
    never = policy.get("no-quarantine", [])
    raw_entries = data.get("exception", [])
    entries = []
    for raw in raw_entries if isinstance(raw_entries, list) else []:
        if not isinstance(raw, dict):
            continue
        description = f"{raw.get('version', '?')}, {raw.get('advisory') or 'no advisory recorded'}"
        entries.append(
            (
                normalize(str(raw.get("package", ""))),
                parse_timestamp(raw.get("cutoff"), what="cutoff"),
                description,
            )
        )
    return (
        days,
        frozenset(normalize(str(n)) for n in never)
        if isinstance(never, list)
        else frozenset(),
        entries,
    )


def user_config_path() -> Path:
    """Return the user-level uv configuration file of the runner."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "uv" / "uv.toml"


def write_user_config(exceptions: dict[str, datetime | None]) -> Path:
    """Put the lock's exceptions in the user-level uv configuration, so ``uv sync --locked`` accepts the lock as it is."""
    path = user_config_path()
    rest = _BLOCK.sub("", path.read_text() if path.exists() else "").lstrip("\n")
    items = ", ".join(
        f"{name} = false"
        if cutoff is None
        else f'{name} = "{format_timestamp(cutoff)}"'
        for name, cutoff in sorted(exceptions.items())
    )
    block = f"{BLOCK_BEGIN}\nexclude-newer-package = {{ {items} }}\n{BLOCK_END}\n"
    merged = f"{block}\n{rest}" if rest else block
    tomllib.loads(merged)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(merged)
    return path


def main(argv: list[str]) -> int:
    """Check the lock against the list, configure uv for it, and annotate the job."""
    if len(argv) != 3:
        print(
            f"usage: {argv[0]} <uv.lock> <quarantine-exceptions.toml>", file=sys.stderr
        )
        return 2
    lock_path, list_path = Path(argv[1]), Path(argv[2])
    if not lock_path.is_file():
        print(f"{lock_path} not found: nothing to check")
        return 0
    lock = lock_exceptions(lock_path.read_text())
    if not lock:
        print(f"{lock_path} records no quarantine exceptions")
        return 0
    days, never, entries = load_list(list_path.read_text())
    now = datetime.now(UTC)
    failed = False
    for name, cutoff in lock.items():
        if cutoff is None:
            if name in never:
                print(
                    f"::notice title=quarantine exception::{name} is never quarantined (Eye2Gene package)"
                )
            else:
                print(
                    f"::error title=unlisted quarantine exception::{lock_path} lets {name} in without any quarantine"
                )
                failed = True
            continue
        covering = [
            entry for entry in entries if entry[0] == name and entry[1] >= cutoff
        ]
        expires = cutoff + timedelta(days=days)
        if not covering and now < expires:
            print(
                f"::error title=unlisted quarantine exception::{lock_path} lets {name} in up to "
                f"{format_timestamp(cutoff)}, which quarantine-exceptions.toml in {LIST_REPO} does not allow"
            )
            failed = True
            continue
        description = (
            min(covering, key=lambda entry: entry[1])[2]
            if covering
            else "no longer in the list"
        )
        if now >= expires:
            print(
                f"::warning title=expired quarantine exception::{name}: releases up to "
                f"{format_timestamp(cutoff)} allowed ({description}; expired {expires:%Y-%m-%d}): "
                f"it now only pins {name}; `just up` drops it"
            )
        else:
            print(
                f"::notice title=quarantine exception::{name}: releases up to "
                f"{format_timestamp(cutoff)} allowed ({description}; expires {expires:%Y-%m-%d})"
            )
    if failed:
        print(
            "::error::list the fix with `just allow <package> [<version>]` in the project; if pyproject.toml sets "
            "exclude-newer-package, remove it, the shared list replaces it, then run `just up`"
        )
        return 1
    print(f"uv configured for these exceptions in {write_user_config(lock)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
