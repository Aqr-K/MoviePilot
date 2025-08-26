"""
Plugin Database Management System

This module provides isolated database model management for plugins,
including plugin-specific Base classes, metadata, and alembic integration.
"""
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from abc import ABC, abstractmethod

from sqlalchemy import MetaData, create_engine, text, inspect
from sqlalchemy.ext.declarative import as_declarative
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import settings
from app.log import logger


class PluginDBConfig:
    """Plugin database configuration"""
    
    def __init__(self, plugin_id: str):
        self.plugin_id = plugin_id.lower()
        self.config_file = self._get_plugin_config_file()
        self._config: Dict[str, Any] = {}
        self._load_config()
    
    def _get_plugin_config_file(self) -> Path:
        """Get plugin database config file path"""
        plugin_dir = settings.ROOT_PATH / "app" / "plugins" / self.plugin_id
        if not plugin_dir.exists():
            # Try to find plugin directory case-insensitively
            plugins_dir = settings.ROOT_PATH / "app" / "plugins"
            if plugins_dir.exists():
                for item in plugins_dir.iterdir():
                    if item.is_dir() and item.name.lower() == self.plugin_id:
                        plugin_dir = item
                        break
                        
        return plugin_dir / "plugin_db_config.json"
    
    def _load_config(self):
        """Load plugin database configuration"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load plugin DB config for {self.plugin_id}: {e}")
                self._config = {}
        else:
            # Create default config
            self._config = self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default plugin database configuration"""
        plugin_dir = self.config_file.parent
        return {
            "models_dir": str(plugin_dir / "models"),
            "base_class_name": f"Plugin{self.plugin_id.title()}Base",
            "versions_dir": str(plugin_dir / "alembic" / "versions"),
            "alembic_dir": str(plugin_dir / "alembic"),
            "branch_label": f"plugin_{self.plugin_id}"
        }
    
    def save_config(self):
        """Save plugin database configuration"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save plugin DB config for {self.plugin_id}: {e}")
    
    @property
    def models_dir(self) -> Path:
        """Get models directory path"""
        return Path(self._config.get("models_dir", self._create_default_config()["models_dir"]))
    
    @property
    def base_class_name(self) -> str:
        """Get base class name"""
        return self._config.get("base_class_name", self._create_default_config()["base_class_name"])
    
    @property
    def versions_dir(self) -> Path:
        """Get alembic versions directory path"""
        return Path(self._config.get("versions_dir", self._create_default_config()["versions_dir"]))
    
    @property
    def alembic_dir(self) -> Path:
        """Get alembic directory path"""
        return Path(self._config.get("alembic_dir", self._create_default_config()["alembic_dir"]))
    
    @property
    def branch_label(self) -> str:
        """Get branch label"""
        return self._config.get("branch_label", self._create_default_config()["branch_label"])


def validate_table_name(plugin_id: str, table_name: str) -> bool:
    """
    Validate that table name follows the required pattern:
    plugin_{plugin_id_lowercase}_{model_name_lowercase}
    
    Args:
        plugin_id: Plugin ID
        table_name: Table name to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    plugin_id_lower = plugin_id.lower()
    expected_prefix = f"plugin_{plugin_id_lower}_"
    
    if not table_name.startswith(expected_prefix):
        return False
    
    # Check if the rest of the name is valid (lowercase, underscore separated)
    suffix = table_name[len(expected_prefix):]
    if not re.match(r'^[a-z][a-z0-9_]*$', suffix):
        return False
    
    return True


class PluginMetaData:
    """Plugin-specific metadata management"""
    
    def __init__(self, plugin_id: str):
        self.plugin_id = plugin_id.lower()
        self.metadata = MetaData(naming_convention={
            "ix": f"ix_plugin_{self.plugin_id}_%(column_0_label)s",
            "uq": f"uq_plugin_{self.plugin_id}_%(table_name)s_%(column_0_name)s",
            "ck": f"ck_plugin_{self.plugin_id}_%(table_name)s_%(constraint_name)s",
            "fk": f"fk_plugin_{self.plugin_id}_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": f"pk_plugin_{self.plugin_id}_%(table_name)s"
        })
    
    def validate_all_tables(self) -> List[str]:
        """
        Validate all tables in metadata follow naming convention
        
        Returns:
            List of invalid table names
        """
        invalid_tables = []
        for table_name in self.metadata.tables.keys():
            if not validate_table_name(self.plugin_id, table_name):
                invalid_tables.append(table_name)
        return invalid_tables


class PluginBaseFactory:
    """Factory for creating plugin-specific Base classes"""
    
    _bases: Dict[str, Any] = {}
    
    @classmethod
    def get_base(cls, plugin_id: str):
        """
        Get or create plugin-specific Base class
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            Plugin-specific Base class
        """
        plugin_id_lower = plugin_id.lower()
        
        if plugin_id_lower not in cls._bases:
            # Create plugin-specific metadata
            plugin_metadata = PluginMetaData(plugin_id_lower)
            
            # Create Base class with plugin-specific metadata
            @as_declarative(metadata=plugin_metadata.metadata)
            class PluginBase:
                """Plugin-specific Base class"""
                
                @classmethod
                def __init_subclass__(cls, **kwargs):
                    super().__init_subclass__(**kwargs)
                    
                    # Validate table name
                    if hasattr(cls, '__tablename__'):
                        if not validate_table_name(plugin_id_lower, cls.__tablename__):
                            raise ValueError(
                                f"Invalid table name '{cls.__tablename__}' for plugin '{plugin_id_lower}'. "
                                f"Must follow pattern 'plugin_{plugin_id_lower}_{{model_name_lowercase}}'"
                            )
                
                def __repr__(self):
                    return f"<{self.__class__.__name__}(plugin={plugin_id_lower})>"
            
            # Set class name
            PluginBase.__name__ = f"Plugin{plugin_id_lower.title()}Base"
            PluginBase.__qualname__ = f"Plugin{plugin_id_lower.title()}Base"
            
            cls._bases[plugin_id_lower] = PluginBase
            
            logger.info(f"Created plugin Base class for {plugin_id_lower}: {PluginBase.__name__}")
        
        return cls._bases[plugin_id_lower]


class PluginDBManager:
    """Plugin database manager"""
    
    def __init__(self):
        self._plugin_configs: Dict[str, PluginDBConfig] = {}
        self._plugin_sessions: Dict[str, sessionmaker] = {}
    
    def get_plugin_config(self, plugin_id: str) -> PluginDBConfig:
        """Get plugin database configuration"""
        plugin_id_lower = plugin_id.lower()
        if plugin_id_lower not in self._plugin_configs:
            self._plugin_configs[plugin_id_lower] = PluginDBConfig(plugin_id_lower)
        return self._plugin_configs[plugin_id_lower]
    
    def get_plugin_base(self, plugin_id: str):
        """Get plugin-specific Base class"""
        return PluginBaseFactory.get_base(plugin_id)
    
    def get_plugin_session(self, plugin_id: str) -> sessionmaker:
        """Get plugin-specific session factory"""
        plugin_id_lower = plugin_id.lower()
        
        if plugin_id_lower not in self._plugin_sessions:
            # Use the main database engine but with plugin-specific session
            # This ensures all plugins use the same database but have isolated metadata
            from app.db import Engine
            self._plugin_sessions[plugin_id_lower] = sessionmaker(bind=Engine)
        
        return self._plugin_sessions[plugin_id_lower]
    
    def initialize_plugin_db(self, plugin_id: str) -> bool:
        """
        Initialize database for a plugin
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            plugin_id_lower = plugin_id.lower()
            
            # Get plugin configuration
            config = self.get_plugin_config(plugin_id_lower)
            
            # Ensure directories exist
            config.models_dir.mkdir(parents=True, exist_ok=True)
            config.versions_dir.mkdir(parents=True, exist_ok=True)
            config.alembic_dir.mkdir(parents=True, exist_ok=True)
            
            # Save configuration
            config.save_config()
            
            # Get plugin Base class to trigger creation
            base_class = self.get_plugin_base(plugin_id_lower)
            
            logger.info(f"Initialized plugin database for {plugin_id_lower}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize plugin database for {plugin_id}: {e}")
            return False
    
    def validate_plugin_models(self, plugin_id: str) -> List[str]:
        """
        Validate plugin models follow naming conventions
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            List of validation errors
        """
        try:
            plugin_id_lower = plugin_id.lower()
            base_class = self.get_plugin_base(plugin_id_lower)
            
            # Get plugin metadata
            plugin_metadata = PluginMetaData(plugin_id_lower)
            
            # Copy tables from base metadata to plugin metadata for validation
            plugin_metadata.metadata.tables.update(base_class.metadata.tables)
            
            # Validate all tables
            invalid_tables = plugin_metadata.validate_all_tables()
            
            errors = []
            for table_name in invalid_tables:
                errors.append(
                    f"Table '{table_name}' does not follow naming convention "
                    f"'plugin_{plugin_id_lower}_{{model_name_lowercase}}'"
                )
            
            return errors
            
        except Exception as e:
            logger.error(f"Failed to validate plugin models for {plugin_id}: {e}")
            return [f"Validation error: {str(e)}"]


# Global plugin database manager instance
plugin_db_manager = PluginDBManager()