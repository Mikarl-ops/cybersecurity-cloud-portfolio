"""Create a filtered copy of an allow-list without modifying the source."""

import argparse
from pathlib import Path


def update_allow_list(import_file, remove_list, output_file):
    """Write a copy with revoked entries removed and return the removed entries."""
    current_allow_list = Path(import_file).read_text(encoding="utf-8").split()
    remove_set = set(remove_list)
    removed = [address for address in current_allow_list if address in remove_set]
    updated = [address for address in current_allow_list if address not in remove_set]
    content = "\n".join(updated)
    if content:
        content += "\n"
    Path(output_file).write_text(content, encoding="utf-8")
    return removed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_file", help="Source allow-list; it is left unchanged")
    parser.add_argument("output_file", help="Path for the filtered copy")
    parser.add_argument("--remove", nargs="+", required=True, help="One or more entries to remove")
    args = parser.parse_args()
    removed = update_allow_list(args.input_file, args.remove, args.output_file)
    print(f"Wrote filtered allow-list to {args.output_file}; removed {len(removed)} entr(y/ies).")


if __name__ == "__main__":
    main()
