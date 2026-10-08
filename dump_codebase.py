"""
استخراج فقط کد اصلی پایتون در یک فایل txt.

ویژگی‌ها:
  - فقط فایل‌های .py را می‌خواند
  - فایل‌های داده‌ای (کامنت/کانفیگ) را نادیده می‌گیرد
  - فایل‌های بزرگ‌تر از MAX_FILE_KB را رد می‌کند
  - خطوط خیلی بلند را کوتاه می‌کند (کانفیگ‌های base64)

طرز استفاده:
    python dump_source.py
    python dump_source.py --include-md      # فایل‌های .md را هم اضافه کن
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime
from pathlib import Path

OUTPUT_NAME = "source_dump.txt"

# حداکثر حجم هر فایل کد (KB) — بیشتر از این یعنی فایل داده‌ای است
MAX_FILE_KB = 200

# حداکثر طول هر خط — خطوط بلندتر کوتاه می‌شوند (مثلاً کانفیگ‌های base64)
MAX_LINE_LENGTH = 500

# پوشه‌های نادیده
IGNORE_DIRS = {
    ".git", ".github", ".idea", ".vscode",
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    "node_modules", "build", "dist", "out", "target",
    "github_release", "github_release_stage",
    "qa_artifacts", "_sandbox_appdata",
    "venv", ".venv", "env", ".env",
    "third_party",  # کد شخص ثالث، لازم نیست
    "tests",         # تست‌ها رو جدا نگه می‌داریم
}

# فایل‌هایی که کد اصلی نیستن (داده، کانفیگ، ...)
IGNORE_FILES = {
    "verified_configs.py",   # فقط دیتای ۵۴ کانفیگ
    "source_dump.py",         # خود همین اسکریپت
    "conftest.py",
    "__init__.py",            # معمولاً خالیه
}

# فایل‌های بزرگ که فقط دیتا دارن (بر اساس نام)
IGNORE_PATTERNS = (
    "verified_configs",
    "configs_data",
    "_data.py",
)


def should_read(path: Path) -> bool:
    if path.suffix != ".py":
        return False
    if path.name in IGNORE_FILES:
        return False
    if any(p in path.name for p in IGNORE_PATTERNS):
        return False
    try:
        if path.stat().st_size > MAX_FILE_KB * 1024:
            return False
    except OSError:
        return False
    return True


def collect_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in IGNORE_DIRS and not d.startswith(".")
        )
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if should_read(path):
                files.append(path)
    return files


def truncate_line(line: str, max_len: int = MAX_LINE_LENGTH) -> str:
    if len(line) <= max_len:
        return line
    cut = line.rstrip("\n")
    return cut[:max_len] + f"  ... [خط {len(cut)} کاراکتری کوتاه شد]\n"


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-md", action="store_true",
                        help="فایل‌های .md را هم اضافه کن")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    output = root / OUTPUT_NAME
    files = collect_files(root)

    if not files:
        print("هیچ فایل پایتونی پیدا نشد!")
        return

    total_bytes = 0

    with output.open("w", encoding="utf-8", errors="replace", newline="\n") as out:
        # هدر
        out.write("=" * 80 + "\n")
        out.write("PYTHON SOURCE DUMP (code only)\n")
        out.write("=" * 80 + "\n")
        out.write(f"Root      : {root}\n")
        out.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"Files     : {len(files)}\n")
        out.write(f"Max size  : {MAX_FILE_KB} KB per file\n")
        out.write("=" * 80 + "\n\n")

        # فهرست
        out.write("TABLE OF CONTENTS\n")
        out.write("-" * 80 + "\n")
        for idx, path in enumerate(files, 1):
            rel = path.relative_to(root)
            size = path.stat().st_size
            lines = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
            out.write(f"{idx:4d}. {rel}   ({human_size(size)}, {lines} خط)\n")
        out.write("\n\n")

        # محتوا
        for idx, path in enumerate(files, 1):
            rel = path.relative_to(root)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                print(f"⚠ رد شد {rel}: {exc}")
                continue

            # کوتاه کردن خطوط بلند
            lines = content.splitlines(keepends=True)
            lines = [truncate_line(ln) for ln in lines]
            content = "".join(lines)

            size = len(content.encode("utf-8"))
            total_bytes += size

            out.write("=" * 80 + "\n")
            out.write(f"FILE #{idx}: {rel}\n")
            out.write(f"PATH: {rel}\n")
            out.write(f"SIZE: {human_size(size)}\n")
            out.write("=" * 80 + "\n\n")
            out.write(content)
            if not content.endswith("\n"):
                out.write("\n")
            out.write("\n\n")

    print()
    print("✅ دامپ ساخته شد!")
    print(f"   📄 خروجی     : {output}")
    print(f"   📊 تعداد فایل: {len(files)}")
    print(f"   💾 حجم کل    : {human_size(total_bytes)}")


if __name__ == "__main__":
    main()