"""Turn a meeting transcript into short notes. Standard library only."""
import sys
from pathlib import Path

MARKERS = ("action", "todo", "decided", "decision", "owner")


def main():
    if len(sys.argv) != 2:
        print("usage: notes.py <transcript.txt>")
        return 1
    source = Path(sys.argv[1])
    lines = [line.strip() for line in source.read_text(encoding="utf-8").splitlines()]
    kept = [line for line in lines if line and any(m in line.lower() for m in MARKERS)]
    target = source.with_suffix(".notes.md")
    target.write_text("# Notes\n\n" + "\n".join("- " + line for line in kept) + "\n",
                      encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
