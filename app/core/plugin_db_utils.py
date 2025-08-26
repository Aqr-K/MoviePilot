"""
Plugin Database Utilities

Utility functions and decorators for plugin database integration.
"""
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Type
import inspect

from sqlalchemy.orm import Session

from app.core.plugin_db import plugin_db_manager
from app.core.plugin_alembic import plugin_alembic_manager, plugin_version_manager
from app.log import logger

F = TypeVar('F', bound=Callable[..., Any])


def with_plugin_db(plugin_id: Optional[str] = None):
    """
    Decorator to automatically provide plugin-specific database session
    
    Args:
        plugin_id: Plugin ID (if None, tries to infer from class)
    
    Usage:
        @with_plugin_db()
        def my_method(self, db: Session):
            # db is automatically provided as plugin-specific session
            pass
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Try to infer plugin_id if not provided
            actual_plugin_id = plugin_id
            if not actual_plugin_id and args:
                # Try to get plugin_id from the first argument (usually 'self')
                obj = args[0]
                if hasattr(obj, '__class__'):
                    class_name = obj.__class__.__name__
                    # Remove common suffixes to get plugin ID
                    for suffix in ['Plugin', 'Base', 'Model']:
                        if class_name.endswith(suffix):
                            class_name = class_name[:-len(suffix)]
                            break
                    actual_plugin_id = class_name.lower()
            
            if not actual_plugin_id:
                raise ValueError("Could not determine plugin_id. Please provide it explicitly.")
            
            # Get plugin-specific session
            session_factory = plugin_db_manager.get_plugin_session(actual_plugin_id)
            
            # Check if function expects a db parameter
            sig = inspect.signature(func)
            if 'db' in sig.parameters:
                # Provide db session
                with session_factory() as db:
                    try:
                        result = func(*args, db=db, **kwargs)
                        db.commit()
                        return result
                    except Exception:
                        db.rollback()
                        raise
            else:
                # Function doesn't need db parameter
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


class PluginModel:
    """
    Base mixin for plugin models that provides utility methods
    """
    
    @classmethod
    def get_plugin_id(cls) -> str:
        """Get plugin ID from table name"""
        table_name = cls.__tablename__
        if not table_name.startswith('plugin_'):
            raise ValueError(f"Invalid table name {table_name}. Must start with 'plugin_'")
        
        # Extract plugin_id from table name: plugin_{plugin_id}_{model_name}
        parts = table_name.split('_')
        if len(parts) < 3:
            raise ValueError(f"Invalid table name {table_name}. Must follow pattern 'plugin_{{plugin_id}}_{{model_name}}'")
        
        return parts[1]
    
    @classmethod
    def get_plugin_session(cls) -> Session:
        """Get plugin-specific database session"""
        plugin_id = cls.get_plugin_id()
        session_factory = plugin_db_manager.get_plugin_session(plugin_id)
        return session_factory()
    
    @classmethod
    @with_plugin_db()
    def create_all_tables(cls, db: Session):
        """Create all tables for this plugin"""
        plugin_id = cls.get_plugin_id()
        base_class = plugin_db_manager.get_plugin_base(plugin_id)
        base_class.metadata.create_all(bind=db.bind)
        logger.info(f"Created all tables for plugin {plugin_id}")
    
    @classmethod
    @with_plugin_db()
    def drop_all_tables(cls, db: Session):
        """Drop all tables for this plugin"""
        plugin_id = cls.get_plugin_id()
        base_class = plugin_db_manager.get_plugin_base(plugin_id)
        base_class.metadata.drop_all(bind=db.bind)
        logger.info(f"Dropped all tables for plugin {plugin_id}")


def create_plugin_model(plugin_id: str, model_name: str, **columns) -> Type:
    """
    Dynamically create a plugin model class
    
    Args:
        plugin_id: Plugin ID
        model_name: Model name (will be converted to lowercase)
        **columns: Column definitions
        
    Returns:
        Model class
        
    Example:
        UserModel = create_plugin_model(
            'mytest', 'user',
            id=Column(Integer, primary_key=True),
            name=Column(String(50))
        )
    """
    from sqlalchemy import Column
    
    # Get plugin Base class
    base_class = plugin_db_manager.get_plugin_base(plugin_id)
    
    # Create table name following convention
    table_name = f"plugin_{plugin_id.lower()}_{model_name.lower()}"
    
    # Create model class
    class_name = f"Plugin{plugin_id.title()}{model_name.title()}"
    
    # Build class attributes
    attrs = {
        '__tablename__': table_name,
        '__module__': f'plugin_{plugin_id.lower()}.models',
        **columns
    }
    
    # Create the class
    model_class = type(class_name, (base_class, PluginModel), attrs)
    
    logger.info(f"Created plugin model {class_name} for plugin {plugin_id}")
    return model_class


def initialize_plugin_database(plugin_id: str, create_config: bool = True, upgrade_db: bool = True) -> bool:
    """
    Initialize database for a plugin
    
    Args:
        plugin_id: Plugin ID
        create_config: Whether to create alembic configuration
        upgrade_db: Whether to upgrade database to latest
        
    Returns:
        bool: True if successful
    """
    try:
        plugin_id_lower = plugin_id.lower()
        
        # Initialize plugin database
        if not plugin_db_manager.initialize_plugin_db(plugin_id_lower):
            return False
        
        # Create alembic configuration
        if create_config:
            if not plugin_alembic_manager.create_plugin_alembic_config(plugin_id_lower):
                logger.warning(f"Failed to create alembic config for {plugin_id_lower}")
        
        # Upgrade database
        if upgrade_db:
            if not plugin_alembic_manager.upgrade_plugin_database(plugin_id_lower):
                logger.warning(f"Failed to upgrade database for {plugin_id_lower}")
        
        logger.info(f"Successfully initialized database for plugin {plugin_id_lower}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database for plugin {plugin_id}: {e}")
        return False


def cleanup_plugin_database(plugin_id: str, remove_tables: bool = False) -> bool:
    """
    Cleanup database for a plugin
    
    Args:
        plugin_id: Plugin ID
        remove_tables: Whether to drop plugin tables
        
    Returns:
        bool: True if successful
    """
    try:
        plugin_id_lower = plugin_id.lower()
        
        # Remove orphaned versions for this plugin
        orphaned = plugin_version_manager.find_orphaned_versions()
        if plugin_id_lower in orphaned:
            deleted = plugin_version_manager.cleanup_orphaned_versions(dry_run=False)
            if plugin_id_lower in deleted:
                logger.info(f"Cleaned up {len(deleted[plugin_id_lower])} orphaned versions for plugin {plugin_id_lower}")
        
        # Optionally drop tables
        if remove_tables:
            try:
                base_class = plugin_db_manager.get_plugin_base(plugin_id_lower)
                session_factory = plugin_db_manager.get_plugin_session(plugin_id_lower)
                
                with session_factory() as db:
                    base_class.metadata.drop_all(bind=db.bind)
                    db.commit()
                    logger.info(f"Dropped all tables for plugin {plugin_id_lower}")
            except Exception as e:
                logger.warning(f"Failed to drop tables for plugin {plugin_id_lower}: {e}")
        
        logger.info(f"Successfully cleaned up database for plugin {plugin_id_lower}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to cleanup database for plugin {plugin_id}: {e}")
        return False


def validate_plugin_database(plugin_id: str) -> Dict[str, Any]:
    """
    Validate plugin database setup
    
    Args:
        plugin_id: Plugin ID
        
    Returns:
        Dict with validation results
    """
    results = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'info': []
    }
    
    try:
        plugin_id_lower = plugin_id.lower()
        
        # Validate models
        model_errors = plugin_db_manager.validate_plugin_models(plugin_id_lower)
        if model_errors:
            results['errors'].extend(model_errors)
            results['valid'] = False
        
        # Validate versions
        version_errors = plugin_version_manager.validate_plugin_versions(plugin_id_lower)
        if version_errors:
            results['warnings'].extend(version_errors)
        
        # Check configuration
        try:
            config = plugin_db_manager.get_plugin_config(plugin_id_lower)
            if not config.config_file.exists():
                results['info'].append("Plugin database config file does not exist (will be created)")
            
            if not config.alembic_dir.exists():
                results['info'].append("Plugin alembic directory does not exist (will be created)")
        except Exception as e:
            results['errors'].append(f"Config validation error: {str(e)}")
            results['valid'] = False
        
        # Check for orphaned versions
        orphaned = plugin_version_manager.find_orphaned_versions()
        if plugin_id_lower in orphaned:
            results['warnings'].append(f"Found {len(orphaned[plugin_id_lower])} orphaned versions")
        
    except Exception as e:
        results['errors'].append(f"Validation error: {str(e)}")
        results['valid'] = False
    
    return results


def get_plugin_database_info(plugin_id: str) -> Dict[str, Any]:
    """
    Get plugin database information
    
    Args:
        plugin_id: Plugin ID
        
    Returns:
        Dict with plugin database info
    """
    info = {}
    
    try:
        plugin_id_lower = plugin_id.lower()
        
        # Basic info
        info['plugin_id'] = plugin_id_lower
        info['initialized'] = False
        info['has_models'] = False
        info['has_alembic'] = False
        info['current_revision'] = None
        info['table_count'] = 0
        info['tables'] = []
        
        # Check if initialized
        try:
            config = plugin_db_manager.get_plugin_config(plugin_id_lower)
            info['config_exists'] = config.config_file.exists()
            info['alembic_dir_exists'] = config.alembic_dir.exists()
            info['versions_dir_exists'] = config.versions_dir.exists()
            info['initialized'] = config.config_file.exists()
        except Exception as e:
            info['config_error'] = str(e)
        
        # Check models
        try:
            base_class = plugin_db_manager.get_plugin_base(plugin_id_lower)
            tables = list(base_class.metadata.tables.keys())
            info['has_models'] = len(tables) > 0
            info['table_count'] = len(tables)
            info['tables'] = tables
        except Exception as e:
            info['model_error'] = str(e)
        
        # Check alembic
        try:
            current_rev = plugin_alembic_manager.get_plugin_current_revision(plugin_id_lower)
            info['current_revision'] = current_rev
            info['has_alembic'] = current_rev is not None
        except Exception as e:
            info['alembic_error'] = str(e)
        
    except Exception as e:
        info['error'] = str(e)
    
    return info