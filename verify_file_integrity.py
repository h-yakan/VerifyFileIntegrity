#!/usr/bin/env python3
import argparse
import csv
import hashlib
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class FileRecord:
    relative_path: str
    file_size_bytes: int
    modified_time_utc_iso: str
    sha256_hex: str


def parse_extensions(extensions: Optional[List[str]]) -> Set[str]:
    if not extensions:
        return {".py", ".env"}
    parsed: Set[str] = set()
    for ext in extensions:
        if not ext:
            continue
        parts = [p.strip() for p in ext.split(",") if p.strip()]
        for p in parts:
            parsed.add(p if p.startswith(".") else f".{p}")
    return parsed


def iter_files(root_dir: str, allowed_extensions: Set[str]) -> Iterable[str]:
    root_dir_abs = os.path.abspath(root_dir)
    for current_dir, dirnames, filenames in os.walk(root_dir_abs):
        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if allowed_extensions and ext not in allowed_extensions:
                continue
            absolute_path = os.path.join(current_dir, filename)
            yield os.path.relpath(absolute_path, root_dir_abs)


def sha256_of_file(absolute_path: str) -> str:
    hasher = hashlib.sha256()
    with open(absolute_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def to_iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).replace(microsecond=0).isoformat()


def build_inventory(root_dir: str, allowed_extensions: Set[str]) -> List[FileRecord]:
    root_dir_abs = os.path.abspath(root_dir)
    records: List[FileRecord] = []
    for relative_path in iter_files(root_dir_abs, allowed_extensions):
        absolute_path = os.path.join(root_dir_abs, relative_path)
        stat = os.stat(absolute_path)
        record = FileRecord(
            relative_path=relative_path.replace("\\", "/"),
            file_size_bytes=stat.st_size,
            modified_time_utc_iso=to_iso_utc(stat.st_mtime),
            sha256_hex=sha256_of_file(absolute_path),
        )
        records.append(record)
    records.sort(key=lambda r: r.relative_path.lower())
    return records


def write_inventory_csv(records: List[FileRecord], output_file: str) -> None:
    output_dir = os.path.dirname(os.path.abspath(output_file))
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "size", "mtime_utc", "sha256"])
        for r in records:
            writer.writerow([r.relative_path, str(r.file_size_bytes), r.modified_time_utc_iso, r.sha256_hex])


def read_inventory_csv(input_file: str) -> Dict[str, FileRecord]:
    inventory: Dict[str, FileRecord] = {}
    with open(input_file, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            path = row["path"].strip()
            size = int(row["size"]) if row.get("size") else 0
            mtime = row.get("mtime_utc", "")
            sha256 = row.get("sha256", "")
            inventory[path] = FileRecord(
                relative_path=path,
                file_size_bytes=size,
                modified_time_utc_iso=mtime,
                sha256_hex=sha256,
            )
    return inventory


@dataclass
class CheckResult:
    new_files: List[FileRecord]
    deleted_files: List[FileRecord]
    modified_files: List[Tuple[FileRecord, FileRecord]]  # (baseline, current)


def check_against_inventory(
    root_dir: str,
    allowed_extensions: Set[str],
    baseline: Dict[str, FileRecord],
) -> CheckResult:
    current_records = build_inventory(root_dir, allowed_extensions)
    current_by_path: Dict[str, FileRecord] = {r.relative_path: r for r in current_records}

    baseline_paths = set(baseline.keys())
    current_paths = set(current_by_path.keys())

    new_paths = sorted(current_paths - baseline_paths, key=str.lower)
    deleted_paths = sorted(baseline_paths - current_paths, key=str.lower)
    common_paths = baseline_paths & current_paths

    new_files = [current_by_path[p] for p in new_paths]
    deleted_files = [baseline[p] for p in deleted_paths]

    modified_files: List[Tuple[FileRecord, FileRecord]] = []
    for p in sorted(common_paths, key=str.lower):
        base_rec = baseline[p]
        cur_rec = current_by_path[p]
        if base_rec.sha256_hex != cur_rec.sha256_hex:
            modified_files.append((base_rec, cur_rec))

    return CheckResult(new_files=new_files, deleted_files=deleted_files, modified_files=modified_files)


def format_report(result: CheckResult) -> str:
    lines: List[str] = []
    lines.append("VerifyFileIntegrity Report")
    lines.append(to_iso_utc(datetime.now(tz=timezone.utc).timestamp()))
    lines.append("")

    lines.append(f"Toplam Yeni Dosya: {len(result.new_files)}")
    lines.append(f"Toplam Silinmiş Dosya: {len(result.deleted_files)}")
    lines.append(f"Toplam Değiştirilmiş Dosya: {len(result.modified_files)}")
    lines.append("")

    if result.new_files:
        lines.append("[Yeni Dosyalar]")
        for r in result.new_files:
            lines.append(f"+ {r.relative_path} | {r.file_size_bytes} B | {r.modified_time_utc_iso}")
        lines.append("")

    if result.deleted_files:
        lines.append("[Silinmiş Dosyalar]")
        for r in result.deleted_files:
            lines.append(f"- {r.relative_path} | {r.file_size_bytes} B | {r.modified_time_utc_iso}")
        lines.append("")

    if result.modified_files:
        lines.append("[Değiştirilmis Dosyalar]")
        for base_rec, cur_rec in result.modified_files:
            lines.append(
                f"* {base_rec.relative_path}\n  eski: {base_rec.file_size_bytes} B | {base_rec.modified_time_utc_iso} | {base_rec.sha256_hex[:12]}...\n  yeni: {cur_rec.file_size_bytes} B | {cur_rec.modified_time_utc_iso} | {cur_rec.sha256_hex[:12]}..."
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_text(content: str, output_file: str) -> None:
    output_dir = os.path.dirname(os.path.abspath(output_file))
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(content)

# --- Config support start ---
try:
    import configparser
except Exception:
    configparser = None  # Fallback if unavailable; we'll handle at runtime


def _find_default_config_path(explicit_path: Optional[str]) -> Optional[str]:
    if explicit_path:
        return explicit_path
    candidate = os.path.abspath("verify_file_integrity.ini")
    return candidate if os.path.exists(candidate) else None


def _load_config_section(
    section_name: str, config_path: Optional[str]
) -> Dict[str, str]:
    if not config_path:
        return {}
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config dosyasi bulunamadi: {config_path}")
    if configparser is None:
        raise RuntimeError("configparser modulu kullanilamiyor")
    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")
    if not parser.has_section(section_name):
        return {}
    section = {k: v for k, v in parser.items(section_name)}
    return section


def _merge_build_params(args: argparse.Namespace) -> Tuple[str, List[str], str]:
    config_path = _find_default_config_path(getattr(args, "config", None))
    section = _load_config_section("build", config_path)

    # Prefer CLI over config; fall back to defaults where present
    root = (
        args.root
        if getattr(args, "root", None) is not None
        else section.get("root", ".")
    )

    ext_cli: Optional[List[str]] = getattr(args, "ext", None)
    if ext_cli is not None:
        ext_list = ext_cli
    else:
        ext_value = section.get("ext")
        ext_list = [ext_value] if ext_value else None

    output = args.output if getattr(args, "output", None) else section.get("output")

    if not output:
        raise ValueError(
            "'output' degeri gerekli. CLI --output veya [build] output ile verin."
        )

    return root, (ext_list or []), output


def _merge_check_params(
    args: argparse.Namespace,
) -> Tuple[str, List[str], str, Optional[str]]:
    config_path = _find_default_config_path(getattr(args, "config", None))
    section = _load_config_section("check", config_path)

    root = (
        args.root
        if getattr(args, "root", None) is not None
        else section.get("root", ".")
    )

    ext_cli: Optional[List[str]] = getattr(args, "ext", None)
    if ext_cli is not None:
        ext_list = ext_cli
    else:
        ext_value = section.get("ext")
        ext_list = [ext_value] if ext_value else None

    input_path = args.input if getattr(args, "input", None) else section.get("input")
    if not input_path:
        raise ValueError(
            "'input' degeri gerekli. CLI --input veya [check] input ile verin."
        )

    report_path = (
        args.report if getattr(args, "report", None) else section.get("report")
    )

    return root, (ext_list or []), input_path, report_path


# --- Config support end ---


def build_command(args: argparse.Namespace) -> int:
    exts = parse_extensions(args.ext)
    records = build_inventory(args.root, exts)
    write_inventory_csv(records, args.output)
    print(f"Envanter oluşturuldu: {args.output} ({len(records)} kayıt)")
    return 0


def check_command(args: argparse.Namespace) -> int:
    exts = parse_extensions(args.ext)
    baseline = read_inventory_csv(args.input)
    result = check_against_inventory(args.root, exts, baseline)

    report_text = format_report(result)
    if args.report:
        write_text(report_text, args.report)
        print(f"Rapor kaydedildi: {args.report}")
    else:
        print(report_text)

    print(
        f"Yeni: {len(result.new_files)}, Silinmiş: {len(result.deleted_files)}, Değiştirilmiş: {len(result.modified_files)}"
    )

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifyfileintegrity",
        description=(
            "Alt klasörleri tarayarak belirli uzantılı dosyalar için hash envanteri oluşturur ve doğrular."
        ),
    )
    # Global config option
    parser.add_argument(
        "--config",
        help="INI formatında ayarlar dosyası. [build] ve [check] bölümleri desteklenir.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser(
        "build", help="Dosya envanteri oluştur (path, size, mtime, sha256)"
    )
    build_parser.add_argument(
        "--root", default=None, help="Taranacak kök dizin (config yoksa varsayılan: .)"
    )
    build_parser.add_argument(
        "--ext",
        action="append",
        help="Dahil edilecek uzantılar. Birden fazla kez veya virgülle kullanın. Örn: --ext .py --ext .env,.txt",
    )
    build_parser.add_argument(
        "--output",
        default=None,
        help="Oluşan envanter CSV dosyası yolu (config ile verilebilir)",
    )
    build_parser.set_defaults(func=build_command)

    check_parser = subparsers.add_parser(
        "check", help="Önceki envantere göre değişiklikleri kontrol et"
    )
    check_parser.add_argument(
        "--root", default=None, help="Taranacak kök dizin (config yoksa varsayılan: .)"
    )
    check_parser.add_argument(
        "--ext",
        action="append",
        help="Dahil edilecek uzantılar. Envanter ile uyumlu olması önerilir. Örn: --ext .py --ext .env,.txt",
    )
    check_parser.add_argument(
        "--input",
        default=None,
        help="Önceki envanter CSV dosyası yolu (config ile verilebilir)",
    )
    check_parser.add_argument(
        "--report",
        help="Raporun kaydedileceği dosya yolu (verilmezse konsola yazılır; config ile verilebilir)",
    )
    check_parser.set_defaults(func=check_command)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # Merge config values into args before dispatch
    if args.command == "build":
        try:
            root, ext_list, output = _merge_build_params(args)
        except Exception as e:
            print(f"Hata: {e}")
            return 2
        args.root = root
        args.ext = ext_list
        args.output = output
    elif args.command == "check":
        try:
            root, ext_list, input_path, report_path = _merge_check_params(args)
        except Exception as e:
            print(f"Hata: {e}")
            return 2
        args.root = root
        args.ext = ext_list
        args.input = input_path
        args.report = report_path

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("İptal edildi.")
        return 130
    except FileNotFoundError as e:
        print(f"Hata: Dosya bulunamadı: {e}")
        return 2
    except Exception as e:
        print(f"Beklenmeyen hata: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
