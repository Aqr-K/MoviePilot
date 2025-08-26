"""
Plugin Alembic Management System

This module provides alembic integration for plugin database models,
including migration generation, orphan cleanup, and branch isolation.
"""
import os
import shutil
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
import re

from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from alembic.command import init as alembic_init
from alembic.command import revision as alembic_revision
from alembic.command import upgrade as alembic_upgrade
from alembic.command import current as alembic_current
from alembic.operations import Operations
from alembic.migration import MigrationContext
from sqlalchemy import text, MetaData

from app.core.config import settings
from app.core.plugin_db import plugin_db_manager, PluginDBConfig
from app.db import Engine, SessionFactory
from app.log import logger


class PluginAlembicManager:
    """Plugin Alembic management system"""
    
    def __init__(self):
        self.main_database_dir = settings.ROOT_PATH / "database"
        self.main_env_path = self.main_database_dir / "env.py"
        self.main_script_template = self.main_database_dir / "script.py.mako"
    
    def create_plugin_alembic_config(self, plugin_id: str) -> bool:
        """
        Create alembic configuration for a plugin
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            plugin_id_lower = plugin_id.lower()
            config = plugin_db_manager.get_plugin_config(plugin_id_lower)
            
            # Create alembic directory structure
            alembic_dir = config.alembic_dir
            alembic_dir.mkdir(parents=True, exist_ok=True)
            config.versions_dir.mkdir(parents=True, exist_ok=True)
            
            # Create plugin-specific env.py
            self._create_plugin_env_file(plugin_id_lower, config)
            
            # Create plugin-specific script template
            self._create_plugin_script_template(config)
            
            # Create plugin-specific alembic.ini
            self._create_plugin_alembic_ini(plugin_id_lower, config)
            
            logger.info(f"Created alembic configuration for plugin {plugin_id_lower}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create alembic config for plugin {plugin_id}: {e}")
            return False
    
    def _create_plugin_env_file(self, plugin_id: str, config: PluginDBConfig):
        """Create plugin-specific env.py file"""
        plugin_env_path = config.alembic_dir / "env.py"
        
        env_content = f'''"""
Plugin {plugin_id} Alembic Environment

This file is auto-generated and should not be modified directly.
It provides isolated database migration environment for plugin {plugin_id}.
"""
import sys
from pathlib import Path
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool, text
from alembic import context

# Add project root to Python path
project_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(project_root))

from app.core.plugin_db import plugin_db_manager
from app.db import Engine

# Plugin configuration
PLUGIN_ID = "{plugin_id}"
BRANCH_LABEL = "{config.branch_label}"

# This is the Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Get plugin-specific Base and metadata
plugin_base = plugin_db_manager.get_plugin_base(PLUGIN_ID)
target_metadata = plugin_base.metadata

def get_plugin_versions() -> set:
    """Get version IDs that belong to this plugin branch"""
    try:
        with Engine.connect() as connection:
            # Check if alembic_version table exists
            result = connection.execute(text("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='alembic_version'
            """))
            
            if not result.fetchone():
                return set()
            
            # Get all version IDs with branch label matching this plugin
            result = connection.execute(text("""
                SELECT version_num FROM alembic_version 
                WHERE version_num LIKE :pattern
            """), {{"pattern": f"%_{PLUGIN_ID}_%"}})
            
            return {{row[0] for row in result.fetchall()}}
    except Exception as e:
        # If there's any error, return empty set to be safe
        return set()

def filter_plugin_versions(revisions):
    """Filter revisions to only include plugin-specific versions"""
    plugin_versions = get_plugin_versions()
    
    if not plugin_versions:
        return revisions
    
    # Only return revisions that belong to this plugin
    return [rev for rev in revisions if rev.revision in plugin_versions]

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    
    # Configure context for this plugin's metadata only
    if url and "postgresql" in url:
        context.configure(
            url=url,
            target_metadata=target_metadata,
            literal_binds=True,
            dialect_opts={{"paramstyle": "named"}},
            version_table_schema=config.get_main_option('version_table_schema'),
            include_schemas=True,
            include_object=lambda obj, name, type_, reflected, compare_to: (
                type_ == "table" and name.startswith(f"plugin_{{PLUGIN_ID}}_")
            ) if type_ == "table" else True
        )
    else:
        context.configure(
            url=url,
            target_metadata=target_metadata,
            literal_binds=True,
            dialect_opts={{"paramstyle": "named"}},
            render_as_batch=True,
            include_object=lambda obj, name, type_, reflected, compare_to: (
                type_ == "table" and name.startswith(f"plugin_{{PLUGIN_ID}}_")
            ) if type_ == "table" else True
        )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    # Use the main engine
    connectable = Engine

    with connectable.connect() as connection:
        # Configure context for this plugin's metadata only
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=lambda obj, name, type_, reflected, compare_to: (
                type_ == "table" and name.startswith(f"plugin_{{PLUGIN_ID}}_")
            ) if type_ == "table" else True
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
'''
        
        with open(plugin_env_path, 'w', encoding='utf-8') as f:
            f.write(env_content)
    
    def _create_plugin_script_template(self, config: PluginDBConfig):
        """Create plugin-specific script template"""
        template_path = config.alembic_dir / "script.py.mako"
        
        # Copy the main template but add plugin-specific revision ID pattern
        if self.main_script_template.exists():
            shutil.copy2(self.main_script_template, template_path)
        else:
            # Create a default template if main template doesn't exist
            template_content = '''"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
'''
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(template_content)
    
    def _create_plugin_alembic_ini(self, plugin_id: str, config: PluginDBConfig):
        """Create plugin-specific alembic.ini file"""
        ini_path = config.alembic_dir / "alembic.ini"
        
        # Get database URL from settings
        if settings.DB_TYPE.lower() == "postgresql":
            if settings.DB_POSTGRESQL_PASSWORD:
                db_url = f"postgresql://{settings.DB_POSTGRESQL_USERNAME}:{settings.DB_POSTGRESQL_PASSWORD}@{settings.DB_POSTGRESQL_HOST}:{settings.DB_POSTGRESQL_PORT}/{settings.DB_POSTGRESQL_DATABASE}"
            else:
                db_url = f"postgresql://{settings.DB_POSTGRESQL_USERNAME}@{settings.DB_POSTGRESQL_HOST}:{settings.DB_POSTGRESQL_PORT}/{settings.DB_POSTGRESQL_DATABASE}"
        else:
            db_url = f"sqlite:///{settings.CONFIG_PATH}/user.db"
        
        ini_content = f'''# Plugin {plugin_id} Alembic Configuration

[alembic]
# path to migration scripts
script_location = {config.alembic_dir}

# template used to generate migration files
# file_template = %%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library that can be
# installed by adding `alembic[tz]` to the pip requirements
# string value is passed to dateutil.tz.gettz()
# leave blank for localtime
# timezone =

# max length of characters to apply to the
# "slug" field
# truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version_locations specifies additional version script directories
# version_locations = %(here)s/bar:%(here)s/bat:{config.versions_dir}

# version path separator
# version_path_separator = :
# version_path_separator = ;
# version_path_separator = space
version_path_separator = os  # Use os.pathsep. Default is os.pathsep

# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

sqlalchemy.url = {db_url}

[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
'''
        
        with open(ini_path, 'w', encoding='utf-8') as f:
            f.write(ini_content)
    
    def generate_plugin_revision(self, plugin_id: str, message: str, autogenerate: bool = True) -> Optional[str]:
        """
        Generate a new revision for a plugin
        
        Args:
            plugin_id: Plugin ID
            message: Revision message
            autogenerate: Whether to auto-generate migration
            
        Returns:
            Revision ID if successful, None otherwise
        """
        try:
            plugin_id_lower = plugin_id.lower()
            config = plugin_db_manager.get_plugin_config(plugin_id_lower)
            
            # Ensure alembic is configured for this plugin
            if not (config.alembic_dir / "alembic.ini").exists():
                self.create_plugin_alembic_config(plugin_id_lower)
            
            # Create alembic config
            alembic_cfg = AlembicConfig(str(config.alembic_dir / "alembic.ini"))
            alembic_cfg.set_main_option('script_location', str(config.alembic_dir))
            
            # Generate revision with plugin-specific ID pattern
            revision_id = f"{plugin_id_lower}_{message.lower().replace(' ', '_')}"
            
            # Generate the revision
            alembic_revision(
                alembic_cfg, 
                message=f"[{plugin_id}] {message}",
                autogenerate=autogenerate,
                branch_label=config.branch_label,
                rev_id=revision_id
            )
            
            logger.info(f"Generated revision {revision_id} for plugin {plugin_id_lower}")
            return revision_id
            
        except Exception as e:
            logger.error(f"Failed to generate revision for plugin {plugin_id}: {e}")
            return None
    
    def upgrade_plugin_database(self, plugin_id: str, revision: str = "head") -> bool:
        """
        Upgrade plugin database to specified revision
        
        Args:
            plugin_id: Plugin ID
            revision: Target revision (default: "head")
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            plugin_id_lower = plugin_id.lower()
            config = plugin_db_manager.get_plugin_config(plugin_id_lower)
            
            # Ensure alembic is configured for this plugin
            if not (config.alembic_dir / "alembic.ini").exists():
                self.create_plugin_alembic_config(plugin_id_lower)
                return True  # No migrations to run yet
            
            # Create alembic config
            alembic_cfg = AlembicConfig(str(config.alembic_dir / "alembic.ini"))
            alembic_cfg.set_main_option('script_location', str(config.alembic_dir))
            
            # Run upgrade
            alembic_upgrade(alembic_cfg, revision)
            
            logger.info(f"Upgraded plugin {plugin_id_lower} database to {revision}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upgrade plugin {plugin_id} database: {e}")
            return False
    
    def get_plugin_current_revision(self, plugin_id: str) -> Optional[str]:
        """
        Get current revision for a plugin
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            Current revision ID or None
        """
        try:
            plugin_id_lower = plugin_id.lower()
            config = plugin_db_manager.get_plugin_config(plugin_id_lower)
            
            if not (config.alembic_dir / "alembic.ini").exists():
                return None
            
            # Create alembic config
            alembic_cfg = AlembicConfig(str(config.alembic_dir / "alembic.ini"))
            alembic_cfg.set_main_option('script_location', str(config.alembic_dir))
            
            # Get current revision
            script_dir = ScriptDirectory.from_config(alembic_cfg)
            with Engine.connect() as conn:
                context = MigrationContext.configure(conn)
                current_rev = context.get_current_revision()
                
                # Filter to only plugin-specific revisions
                if current_rev and plugin_id_lower in current_rev:
                    return current_rev
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get current revision for plugin {plugin_id}: {e}")
            return None


class PluginVersionManager:
    """Plugin version and orphan management"""
    
    def __init__(self):
        self.alembic_manager = PluginAlembicManager()
    
    def get_all_plugin_versions(self) -> Dict[str, List[str]]:
        """
        Get all plugin versions from alembic_version table
        
        Returns:
            Dict mapping plugin_id to list of version IDs
        """
        plugin_versions = {}
        
        try:
            with SessionFactory() as db:
                # Check if alembic_version table exists
                result = db.execute(text("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='alembic_version'
                """))
                
                if not result.fetchone():
                    return plugin_versions
                
                # Get all version IDs
                result = db.execute(text("SELECT version_num FROM alembic_version"))
                versions = [row[0] for row in result.fetchall()]
                
                # Parse plugin IDs from version numbers
                for version in versions:
                    # Look for plugin-specific version pattern: {plugin_id}_{description}
                    match = re.match(r'^([a-z][a-z0-9_]+?)_', version)
                    if match:
                        plugin_id = match.group(1)
                        if plugin_id.startswith('plugin_'):
                            continue  # Skip if already has plugin_ prefix
                        
                        if plugin_id not in plugin_versions:
                            plugin_versions[plugin_id] = []
                        plugin_versions[plugin_id].append(version)
                
                return plugin_versions
                
        except Exception as e:
            logger.error(f"Failed to get plugin versions: {e}")
            return {}
    
    def find_orphaned_versions(self) -> Dict[str, List[str]]:
        """
        Find orphaned versions (versions for plugins that no longer exist)
        
        Returns:
            Dict mapping plugin_id to list of orphaned version IDs
        """
        orphaned = {}
        
        try:
            # Get all plugin versions from database
            all_plugin_versions = self.get_all_plugin_versions()
            
            # Check which plugins still exist
            plugins_dir = settings.ROOT_PATH / "app" / "plugins"
            existing_plugins = set()
            
            if plugins_dir.exists():
                for item in plugins_dir.iterdir():
                    if item.is_dir() and not item.name.startswith('__'):
                        existing_plugins.add(item.name.lower())
            
            # Find orphaned versions
            for plugin_id, versions in all_plugin_versions.items():
                if plugin_id not in existing_plugins:
                    orphaned[plugin_id] = versions
                    logger.info(f"Found orphaned versions for deleted plugin {plugin_id}: {versions}")
            
            return orphaned
            
        except Exception as e:
            logger.error(f"Failed to find orphaned versions: {e}")
            return {}
    
    def cleanup_orphaned_versions(self, dry_run: bool = True) -> Dict[str, List[str]]:
        """
        Cleanup orphaned versions from alembic_version table
        
        Args:
            dry_run: If True, only report what would be deleted
            
        Returns:
            Dict of versions that were (or would be) deleted
        """
        orphaned_versions = self.find_orphaned_versions()
        
        if not orphaned_versions:
            logger.info("No orphaned versions found")
            return {}
        
        if dry_run:
            logger.info("DRY RUN: Would delete the following orphaned versions:")
            for plugin_id, versions in orphaned_versions.items():
                logger.info(f"  Plugin {plugin_id}: {versions}")
            return orphaned_versions
        
        try:
            deleted = {}
            
            with SessionFactory() as db:
                for plugin_id, versions in orphaned_versions.items():
                    for version in versions:
                        try:
                            db.execute(text(
                                "DELETE FROM alembic_version WHERE version_num = :version"
                            ), {"version": version})
                            
                            if plugin_id not in deleted:
                                deleted[plugin_id] = []
                            deleted[plugin_id].append(version)
                            
                            logger.info(f"Deleted orphaned version {version} for plugin {plugin_id}")
                            
                        except Exception as e:
                            logger.error(f"Failed to delete version {version}: {e}")
                
                db.commit()
            
            logger.info(f"Cleanup complete. Deleted {sum(len(v) for v in deleted.values())} orphaned versions")
            return deleted
            
        except Exception as e:
            logger.error(f"Failed to cleanup orphaned versions: {e}")
            return {}
    
    def validate_plugin_versions(self, plugin_id: str) -> List[str]:
        """
        Validate that plugin versions in database match existing migration files
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            List of validation errors
        """
        errors = []
        
        try:
            plugin_id_lower = plugin_id.lower()
            config = plugin_db_manager.get_plugin_config(plugin_id_lower)
            
            # Get versions from database
            db_versions = self.get_all_plugin_versions().get(plugin_id_lower, [])
            
            # Get versions from files
            file_versions = []
            if config.versions_dir.exists():
                for version_file in config.versions_dir.glob("*.py"):
                    if version_file.name != "__init__.py":
                        # Extract version ID from filename
                        match = re.match(r'^([a-f0-9]+)_', version_file.name)
                        if match:
                            file_versions.append(match.group(1))
            
            # Find mismatches
            db_set = set(db_versions)
            file_set = set(file_versions)
            
            # Versions in DB but not in files
            missing_files = db_set - file_set
            if missing_files:
                errors.append(f"Versions in database but missing files: {list(missing_files)}")
            
            # Versions in files but not in DB
            missing_db = file_set - db_set
            if missing_db:
                errors.append(f"Version files exist but not in database: {list(missing_db)}")
            
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
        
        return errors


# Global instances
plugin_alembic_manager = PluginAlembicManager()
plugin_version_manager = PluginVersionManager()