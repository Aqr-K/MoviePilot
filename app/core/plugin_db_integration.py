"""
Plugin Database System Integration

This module provides integration points for the main plugin system
to work with the plugin database system.
"""
from typing import Dict, List, Any, Optional
from pathlib import Path

from app.core.plugin_db import plugin_db_manager
from app.core.plugin_alembic import plugin_alembic_manager, plugin_version_manager
from app.core.plugin_db_utils import (
    initialize_plugin_database,
    cleanup_plugin_database,
    validate_plugin_database
)
from app.core.config import settings
from app.log import logger


class PluginDatabaseIntegration:
    """Integration layer for plugin database system"""
    
    def __init__(self):
        self._initialized_plugins: Dict[str, bool] = {}
    
    def on_plugin_install(self, plugin_id: str) -> bool:
        """
        Called when a plugin is installed
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            bool: True if successful
        """
        try:
            logger.info(f"Setting up database for newly installed plugin: {plugin_id}")
            
            # Initialize plugin database
            success = initialize_plugin_database(plugin_id)
            
            if success:
                self._initialized_plugins[plugin_id.lower()] = True
                logger.info(f"Successfully set up database for plugin {plugin_id}")
            else:
                logger.error(f"Failed to set up database for plugin {plugin_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error setting up database for plugin {plugin_id}: {e}")
            return False
    
    def on_plugin_uninstall(self, plugin_id: str, remove_data: bool = False) -> bool:
        """
        Called when a plugin is uninstalled
        
        Args:
            plugin_id: Plugin ID
            remove_data: Whether to remove plugin data (tables)
            
        Returns:
            bool: True if successful
        """
        try:
            logger.info(f"Cleaning up database for uninstalled plugin: {plugin_id}")
            
            # Cleanup plugin database
            success = cleanup_plugin_database(plugin_id, remove_tables=remove_data)
            
            if success:
                self._initialized_plugins.pop(plugin_id.lower(), None)
                logger.info(f"Successfully cleaned up database for plugin {plugin_id}")
            else:
                logger.error(f"Failed to cleanup database for plugin {plugin_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error cleaning up database for plugin {plugin_id}: {e}")
            return False
    
    def on_plugin_enable(self, plugin_id: str) -> bool:
        """
        Called when a plugin is enabled
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            bool: True if successful
        """
        try:
            plugin_id_lower = plugin_id.lower()
            
            # Check if database is already initialized
            if plugin_id_lower in self._initialized_plugins:
                return True
            
            # Initialize database if not done yet
            success = initialize_plugin_database(plugin_id)
            
            if success:
                self._initialized_plugins[plugin_id_lower] = True
            
            return success
            
        except Exception as e:
            logger.error(f"Error enabling database for plugin {plugin_id}: {e}")
            return False
    
    def on_plugin_disable(self, plugin_id: str) -> bool:
        """
        Called when a plugin is disabled
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            bool: True if successful
        """
        # For now, we don't do anything special when a plugin is disabled
        # The database remains available for when the plugin is re-enabled
        return True
    
    def validate_all_plugins(self) -> Dict[str, Dict[str, Any]]:
        """
        Validate database setup for all plugins
        
        Returns:
            Dict with validation results for each plugin
        """
        results = {}
        
        try:
            # Find all potential plugins
            plugins_dir = settings.ROOT_PATH / "app" / "plugins"
            if not plugins_dir.exists():
                return results
            
            for item in plugins_dir.iterdir():
                if item.is_dir() and not item.name.startswith('__'):
                    plugin_id = item.name
                    try:
                        validation_result = validate_plugin_database(plugin_id)
                        results[plugin_id] = validation_result
                    except Exception as e:
                        results[plugin_id] = {
                            'valid': False,
                            'errors': [f"Validation error: {str(e)}"],
                            'warnings': [],
                            'info': []
                        }
            
        except Exception as e:
            logger.error(f"Error validating all plugins: {e}")
        
        return results
    
    def cleanup_all_orphaned_versions(self, dry_run: bool = True) -> Dict[str, List[str]]:
        """
        Cleanup orphaned versions from all plugins
        
        Args:
            dry_run: If True, only report what would be deleted
            
        Returns:
            Dict of versions that were (or would be) deleted
        """
        try:
            return plugin_version_manager.cleanup_orphaned_versions(dry_run=dry_run)
        except Exception as e:
            logger.error(f"Error cleaning up orphaned versions: {e}")
            return {}
    
    def get_plugin_database_status(self) -> List[Dict[str, Any]]:
        """
        Get database status for all plugins
        
        Returns:
            List of plugin database status info
        """
        status_list = []
        
        try:
            # Find all potential plugins
            plugins_dir = settings.ROOT_PATH / "app" / "plugins"
            if not plugins_dir.exists():
                return status_list
            
            for item in plugins_dir.iterdir():
                if item.is_dir() and not item.name.startswith('__'):
                    plugin_id = item.name
                    try:
                        from app.core.plugin_db_utils import get_plugin_database_info
                        info = get_plugin_database_info(plugin_id)
                        
                        status = {
                            'plugin_id': plugin_id,
                            'initialized': info.get('initialized', False),
                            'has_models': info.get('has_models', False),
                            'has_alembic': info.get('has_alembic', False),
                            'table_count': info.get('table_count', 0),
                            'current_revision': info.get('current_revision'),
                            'error': info.get('error')
                        }
                        
                        status_list.append(status)
                        
                    except Exception as e:
                        status_list.append({
                            'plugin_id': plugin_id,
                            'initialized': False,
                            'has_models': False,
                            'has_alembic': False,
                            'table_count': 0,
                            'current_revision': None,
                            'error': str(e)
                        })
        
        except Exception as e:
            logger.error(f"Error getting plugin database status: {e}")
        
        return status_list
    
    def is_plugin_database_initialized(self, plugin_id: str) -> bool:
        """
        Check if plugin database is initialized
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            bool: True if initialized
        """
        try:
            config = plugin_db_manager.get_plugin_config(plugin_id.lower())
            return config.config_file.exists()
        except Exception:
            return False


# Global integration instance
plugin_db_integration = PluginDatabaseIntegration()