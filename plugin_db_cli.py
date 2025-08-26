#!/usr/bin/env python3
"""
Plugin Database Management CLI

Command-line utility for managing plugin databases, migrations, and cleanup.
"""
import argparse
import sys
from pathlib import Path
from pprint import pprint

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.core.plugin_db_utils import (
    initialize_plugin_database,
    cleanup_plugin_database,
    validate_plugin_database,
    get_plugin_database_info
)
from app.core.plugin_alembic import plugin_alembic_manager, plugin_version_manager
from app.core.plugin_db import plugin_db_manager
from app.core.config import settings
from app.log import logger


def cmd_init(args):
    """Initialize plugin database"""
    print(f"Initializing database for plugin: {args.plugin_id}")
    
    success = initialize_plugin_database(
        args.plugin_id,
        create_config=True,
        upgrade_db=not args.no_upgrade
    )
    
    if success:
        print(f"✓ Successfully initialized database for plugin {args.plugin_id}")
        
        # Show database info
        info = get_plugin_database_info(args.plugin_id)
        print("\nPlugin Database Info:")
        pprint(info)
    else:
        print(f"✗ Failed to initialize database for plugin {args.plugin_id}")
        sys.exit(1)


def cmd_validate(args):
    """Validate plugin database"""
    print(f"Validating database for plugin: {args.plugin_id}")
    
    results = validate_plugin_database(args.plugin_id)
    
    print(f"\nValidation Results for {args.plugin_id}:")
    print(f"Valid: {results['valid']}")
    
    if results['errors']:
        print("\nErrors:")
        for error in results['errors']:
            print(f"  ✗ {error}")
    
    if results['warnings']:
        print("\nWarnings:")
        for warning in results['warnings']:
            print(f"  ⚠ {warning}")
    
    if results['info']:
        print("\nInfo:")
        for info in results['info']:
            print(f"  ℹ {info}")
    
    if not results['valid']:
        sys.exit(1)


def cmd_info(args):
    """Show plugin database information"""
    print(f"Database information for plugin: {args.plugin_id}")
    
    info = get_plugin_database_info(args.plugin_id)
    print("\nPlugin Database Info:")
    pprint(info)


def cmd_migration(args):
    """Create migration for plugin"""
    print(f"Creating migration for plugin: {args.plugin_id}")
    print(f"Message: {args.message}")
    
    revision_id = plugin_alembic_manager.generate_plugin_revision(
        args.plugin_id,
        args.message,
        autogenerate=not args.no_autogenerate
    )
    
    if revision_id:
        print(f"✓ Created migration: {revision_id}")
        
        # Show migration file path
        config = plugin_db_manager.get_plugin_config(args.plugin_id)
        migration_files = list(config.versions_dir.glob("*.py"))
        latest_file = max(migration_files, key=lambda p: p.stat().st_mtime) if migration_files else None
        
        if latest_file:
            print(f"Migration file: {latest_file}")
    else:
        print(f"✗ Failed to create migration for plugin {args.plugin_id}")
        sys.exit(1)


def cmd_upgrade(args):
    """Upgrade plugin database"""
    print(f"Upgrading database for plugin: {args.plugin_id}")
    print(f"Target revision: {args.revision}")
    
    success = plugin_alembic_manager.upgrade_plugin_database(args.plugin_id, args.revision)
    
    if success:
        print(f"✓ Successfully upgraded database for plugin {args.plugin_id}")
        
        # Show current revision
        current = plugin_alembic_manager.get_plugin_current_revision(args.plugin_id)
        if current:
            print(f"Current revision: {current}")
    else:
        print(f"✗ Failed to upgrade database for plugin {args.plugin_id}")
        sys.exit(1)


def cmd_cleanup(args):
    """Cleanup plugin databases"""
    if args.plugin_id:
        print(f"Cleaning up database for plugin: {args.plugin_id}")
        success = cleanup_plugin_database(args.plugin_id, remove_tables=args.remove_tables)
        
        if success:
            print(f"✓ Successfully cleaned up database for plugin {args.plugin_id}")
        else:
            print(f"✗ Failed to cleanup database for plugin {args.plugin_id}")
            sys.exit(1)
    else:
        # Cleanup orphaned versions from all plugins
        print("Cleaning up orphaned versions from all plugins...")
        
        orphaned = plugin_version_manager.find_orphaned_versions()
        if not orphaned:
            print("✓ No orphaned versions found")
            return
        
        print(f"Found orphaned versions for {len(orphaned)} plugins:")
        for plugin_id, versions in orphaned.items():
            print(f"  {plugin_id}: {len(versions)} versions")
        
        if args.dry_run:
            print("\nDry run mode - no changes made")
            return
        
        if not args.force:
            response = input("\nProceed with cleanup? (y/N): ")
            if response.lower() != 'y':
                print("Cleanup cancelled")
                return
        
        deleted = plugin_version_manager.cleanup_orphaned_versions(dry_run=False)
        total_deleted = sum(len(versions) for versions in deleted.values())
        print(f"✓ Cleaned up {total_deleted} orphaned versions")


def cmd_list(args):
    """List plugin databases"""
    print("Plugin Database Status:")
    print("-" * 80)
    
    # Find all potential plugins
    plugins_dir = settings.ROOT_PATH / "app" / "plugins"
    if not plugins_dir.exists():
        print("No plugins directory found")
        return
    
    plugins = []
    for item in plugins_dir.iterdir():
        if item.is_dir() and not item.name.startswith('__'):
            plugins.append(item.name)
    
    if not plugins:
        print("No plugins found")
        return
    
    for plugin_id in sorted(plugins):
        info = get_plugin_database_info(plugin_id)
        
        status_parts = []
        if info.get('initialized', False):
            status_parts.append("✓ Init")
        else:
            status_parts.append("✗ Init")
            
        if info.get('has_models', False):
            status_parts.append(f"📊 {info.get('table_count', 0)} tables")
        
        if info.get('has_alembic', False):
            status_parts.append("🔄 Alembic")
            
        if info.get('current_revision'):
            status_parts.append(f"Rev: {info['current_revision'][:8]}...")
        
        status = " | ".join(status_parts)
        print(f"{plugin_id:20} {status}")
        
        if info.get('error'):
            print(f"{'':20} ✗ Error: {info['error']}")


def main():
    parser = argparse.ArgumentParser(description="Plugin Database Management CLI")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize plugin database')
    init_parser.add_argument('plugin_id', help='Plugin ID')
    init_parser.add_argument('--no-upgrade', action='store_true', 
                            help='Do not run database upgrade after initialization')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate plugin database')
    validate_parser.add_argument('plugin_id', help='Plugin ID')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show plugin database information')
    info_parser.add_argument('plugin_id', help='Plugin ID')
    
    # Migration command
    migration_parser = subparsers.add_parser('migration', help='Create database migration')
    migration_parser.add_argument('plugin_id', help='Plugin ID')
    migration_parser.add_argument('message', help='Migration message')
    migration_parser.add_argument('--no-autogenerate', action='store_true',
                                 help='Do not auto-generate migration content')
    
    # Upgrade command
    upgrade_parser = subparsers.add_parser('upgrade', help='Upgrade plugin database')
    upgrade_parser.add_argument('plugin_id', help='Plugin ID')
    upgrade_parser.add_argument('--revision', default='head', help='Target revision (default: head)')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Cleanup plugin databases')
    cleanup_parser.add_argument('--plugin-id', help='Specific plugin ID to cleanup')
    cleanup_parser.add_argument('--remove-tables', action='store_true',
                               help='Also remove database tables')
    cleanup_parser.add_argument('--dry-run', action='store_true',
                               help='Show what would be cleaned up without making changes')
    cleanup_parser.add_argument('--force', action='store_true',
                               help='Force cleanup without confirmation')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all plugin databases')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        # Route to appropriate command handler
        command_handlers = {
            'init': cmd_init,
            'validate': cmd_validate,
            'info': cmd_info,
            'migration': cmd_migration,
            'upgrade': cmd_upgrade,
            'cleanup': cmd_cleanup,
            'list': cmd_list
        }
        
        handler = command_handlers.get(args.command)
        if handler:
            handler(args)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()