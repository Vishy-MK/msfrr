#!/usr/bin/env python3
"""
Whitelist Management CLI
Command-line tool for managing whitelists
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional
from src.whitelist_manager import get_whitelist_manager, WhitelistType
from tabulate import tabulate


def get_manager():
    """Get whitelist manager"""
    return get_whitelist_manager(data_dir="data")


def add_entry(args):
    """Add whitelist entry"""
    mgr = get_manager()
    
    success, message = mgr.add_entry(
        list_type=args.type,
        list_id=args.list_id,
        pattern=args.pattern,
        description=args.description or "",
        entry_type=args.entry_type or "EXACT",
        created_by=args.user or "cli",
        expires_at=args.expires_at,
        tags=args.tags.split(",") if args.tags else []
    )
    
    if success:
        print(f"✓ {message}")
        sys.exit(0)
    else:
        print(f"✗ Error: {message}")
        sys.exit(1)


def remove_entry(args):
    """Remove whitelist entry"""
    mgr = get_manager()
    
    success, message = mgr.remove_entry(
        list_type=args.type,
        list_id=args.list_id,
        pattern=args.pattern,
        removed_by=args.user or "cli"
    )
    
    if success:
        print(f"✓ {message}")
        sys.exit(0)
    else:
        print(f"✗ Error: {message}")
        sys.exit(1)


def toggle_entry(args):
    """Enable/disable whitelist entry"""
    mgr = get_manager()
    
    success, message = mgr.toggle_entry(
        list_type=args.type,
        list_id=args.list_id,
        pattern=args.pattern,
        enabled=args.enabled,
        toggled_by=args.user or "cli"
    )
    
    if success:
        print(f"✓ {message}")
        sys.exit(0)
    else:
        print(f"✗ Error: {message}")
        sys.exit(1)


def list_entries(args):
    """List whitelist entries"""
    mgr = get_manager()
    
    entries = mgr.get_all_entries(
        list_type=args.type,
        list_id=args.list_id,
        include_disabled=args.include_disabled
    )
    
    if not entries:
        print(f"No entries in {args.type}/{args.list_id}")
        return
    
    # Prepare table data
    table_data = []
    for entry in entries:
        table_data.append([
            entry["pattern"][:40],
            entry["type"],
            "Yes" if entry["enabled"] else "No",
            entry["created_by"],
            entry["description"][:30] if entry["description"] else "-"
        ])
    
    headers = ["Pattern", "Type", "Enabled", "Created By", "Description"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print(f"\nTotal: {len(entries)} entries")


def status(args):
    """Show whitelist status"""
    mgr = get_manager()
    
    status_info = mgr.list_whitelists()
    
    print("\n=== Whitelist Status ===\n")
    for list_type in status_info:
        print(f"{list_type}:")
        if not status_info[list_type]:
            print("  (empty)")
            continue
        
        for list_id, counts in status_info[list_type].items():
            print(f"  {list_id}:")
            print(f"    Total: {counts['total_entries']}")
            print(f"    Active: {counts['active_entries']}")
        print()


def audit_log(args):
    """Show audit log"""
    mgr = get_manager()
    
    logs = mgr.get_audit_log(limit=args.limit)
    
    if not logs:
        print("No audit log entries")
        return
    
    print(f"\n=== Recent Audit Log ({len(logs)} entries) ===\n")
    
    table_data = []
    for entry in logs:
        table_data.append([
            entry["timestamp"][-8:],  # Show only time
            entry["action"],
            f"{entry['list_type']}/{entry['list_id']}",
            entry["pattern"][:30],
            entry["user"]
        ])
    
    headers = ["Time", "Action", "List", "Pattern", "User"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def validate_pattern(args):
    """Validate a pattern"""
    import re
    
    pattern = args.pattern
    test_string = args.test_string
    pattern_type = args.type or "EXACT"
    
    print(f"\nValidating {pattern_type} pattern: {pattern}")
    print(f"Test string: {test_string}\n")
    
    if pattern_type == "EXACT":
        matches = test_string == pattern
    elif pattern_type == "REGEX":
        try:
            matches = bool(re.search(pattern, test_string))
        except re.error as e:
            print(f"✗ Invalid regex: {e}")
            sys.exit(1)
    else:
        print(f"✗ Unknown pattern type: {pattern_type}")
        sys.exit(1)
    
    if matches:
        print(f"✓ Pattern MATCHES: '{test_string}'")
        sys.exit(0)
    else:
        print(f"✗ Pattern DOES NOT MATCH: '{test_string}'")
        sys.exit(1)


def export_config(args):
    """Export whitelist configuration"""
    mgr = get_manager()
    
    # Build export data
    export_data = {}
    for list_type in mgr.whitelists:
        export_data[list_type] = {}
        for list_id, entries in mgr.whitelists[list_type].items():
            export_data[list_type][list_id] = [e.to_dict() for e in entries]
    
    output_file = args.output or "whitelist_export.json"
    
    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    print(f"✓ Configuration exported to: {output_file}")


def import_config(args):
    """Import whitelist configuration"""
    mgr = get_manager()
    
    input_file = args.input
    
    if not Path(input_file).exists():
        print(f"✗ File not found: {input_file}")
        sys.exit(1)
    
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        # Import entries
        count = 0
        for list_type in data:
            for list_id, entries in data[list_type].items():
                for entry_data in entries:
                    success, msg = mgr.add_entry(
                        list_type=list_type,
                        list_id=list_id,
                        pattern=entry_data["pattern"],
                        description=entry_data.get("description", ""),
                        entry_type=entry_data.get("type", "EXACT"),
                        created_by=entry_data.get("created_by", "import"),
                        expires_at=entry_data.get("expires_at"),
                        tags=entry_data.get("tags", [])
                    )
                    if success:
                        count += 1
        
        print(f"✓ Successfully imported {count} entries from {input_file}")
    except Exception as e:
        print(f"✗ Error importing: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Whitelist Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Add entry to global whitelist
  python -m cli add GLOBAL default "sk_test_.*" --type=REGEX --description="Test Stripe keys"
  
  # List profile whitelist
  python -m cli list PROFILE fintech
  
  # Remove entry
  python -m cli remove GLOBAL default "sk_test_.*"
  
  # Toggle entry on/off
  python -m cli toggle GLOBAL default "sk_test_.*" --enable
  
  # Show status
  python -m cli status
  
  # Validate regex pattern
  python -m cli validate "sk_test_.*" "sk_test_123abc" --type=REGEX
  
  # Export configuration
  python -m cli export --output=backup.json
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # ADD command
    add_parser = subparsers.add_parser("add", help="Add whitelist entry")
    add_parser.add_argument("type", choices=["GLOBAL", "PROFILE", "ORGANIZATION"], help="List type")
    add_parser.add_argument("list_id", help="List ID (e.g., 'default', 'fintech', 'org_123')")
    add_parser.add_argument("pattern", help="Pattern to whitelist")
    add_parser.add_argument("--description", help="Description")
    add_parser.add_argument("--type", dest="entry_type", choices=["EXACT", "REGEX"], help="Pattern type")
    add_parser.add_argument("--expires-at", help="Expiration date (ISO format)")
    add_parser.add_argument("--tags", help="Comma-separated tags")
    add_parser.add_argument("--user", help="User adding entry")
    add_parser.set_defaults(func=add_entry)
    
    # REMOVE command
    remove_parser = subparsers.add_parser("remove", help="Remove whitelist entry")
    remove_parser.add_argument("type", choices=["GLOBAL", "PROFILE", "ORGANIZATION"], help="List type")
    remove_parser.add_argument("list_id", help="List ID")
    remove_parser.add_argument("pattern", help="Pattern to remove")
    remove_parser.add_argument("--user", help="User removing entry")
    remove_parser.set_defaults(func=remove_entry)
    
    # TOGGLE command
    toggle_parser = subparsers.add_parser("toggle", help="Enable/disable whitelist entry")
    toggle_parser.add_argument("type", choices=["GLOBAL", "PROFILE", "ORGANIZATION"], help="List type")
    toggle_parser.add_argument("list_id", help="List ID")
    toggle_parser.add_argument("pattern", help="Pattern to toggle")
    toggle_group = toggle_parser.add_mutually_exclusive_group(required=True)
    toggle_group.add_argument("--enable", action="store_true", dest="enabled", help="Enable entry")
    toggle_group.add_argument("--disable", action="store_false", dest="enabled", help="Disable entry")
    toggle_parser.add_argument("--user", help="User toggling entry")
    toggle_parser.set_defaults(func=toggle_entry)
    
    # LIST command
    list_parser = subparsers.add_parser("list", help="List whitelist entries")
    list_parser.add_argument("type", choices=["GLOBAL", "PROFILE", "ORGANIZATION"], help="List type")
    list_parser.add_argument("list_id", help="List ID")
    list_parser.add_argument("--include-disabled", action="store_true", help="Include disabled entries")
    list_parser.set_defaults(func=list_entries)
    
    # STATUS command
    status_parser = subparsers.add_parser("status", help="Show whitelist status")
    status_parser.set_defaults(func=status)
    
    # AUDIT LOG command
    audit_parser = subparsers.add_parser("audit", help="Show audit log")
    audit_parser.add_argument("--limit", type=int, default=100, help="Number of entries to show")
    audit_parser.set_defaults(func=audit_log)
    
    # VALIDATE command
    validate_parser = subparsers.add_parser("validate", help="Validate pattern")
    validate_parser.add_argument("pattern", help="Pattern to validate")
    validate_parser.add_argument("test_string", help="String to test against")
    validate_parser.add_argument("--type", choices=["EXACT", "REGEX"], help="Pattern type")
    validate_parser.set_defaults(func=validate_pattern)
    
    # EXPORT command
    export_parser = subparsers.add_parser("export", help="Export whitelist configuration")
    export_parser.add_argument("--output", help="Output file (default: whitelist_export.json)")
    export_parser.set_defaults(func=export_config)
    
    # IMPORT command
    import_parser = subparsers.add_parser("import", help="Import whitelist configuration")
    import_parser.add_argument("input", help="Input file")
    import_parser.set_defaults(func=import_config)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        args.func(args)
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
