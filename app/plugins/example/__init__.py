"""
Example Plugin

This plugin demonstrates how to use the plugin database system.
It shows how to:
1. Define database models
2. Initialize plugin database
3. Create and run migrations
4. Use plugin-specific database sessions
"""
import json
from typing import Any, List, Dict, Tuple, Optional
from datetime import datetime

from sqlalchemy.orm import Session

from app.plugins import _PluginBase
from app.core.plugin_db_utils import with_plugin_db
from app.log import logger


class ExamplePlugin(_PluginBase):
    """Example plugin demonstrating database functionality"""
    
    # Plugin metadata
    plugin_name = "Database Example"
    plugin_desc = "Demonstrates plugin database system usage"
    plugin_order = 1000
    plugin_icon = "🗃️"
    plugin_version = "1.0.0"
    plugin_author = "MoviePilot"
    author_url = "https://github.com/Aqr-K/MoviePilot"
    
    def __init__(self):
        super().__init__()
        self._enabled = False
        self._db_initialized = False
    
    def init_plugin(self, config: dict = None):
        """Initialize plugin configuration"""
        if not config:
            config = {}
        
        self._enabled = config.get("enabled", False)
        
        if self._enabled and not self._db_initialized:
            self._initialize_database()
        
        logger.info(f"Example plugin initialized, enabled: {self._enabled}")
    
    def _initialize_database(self):
        """Initialize plugin database"""
        try:
            # Initialize plugin database (creates config, alembic setup, etc.)
            if self.init_plugin_database():
                logger.info("Example plugin database initialized successfully")
                
                # Create tables if they don't exist
                self._create_initial_tables()
                
                # Run any pending migrations
                if self.upgrade_plugin_database():
                    logger.info("Example plugin database upgraded successfully")
                    self._db_initialized = True
                else:
                    logger.error("Failed to upgrade example plugin database")
            else:
                logger.error("Failed to initialize example plugin database")
        except Exception as e:
            logger.error(f"Error initializing example plugin database: {e}")
    
    def _create_initial_tables(self):
        """Create initial database tables"""
        try:
            # Import models to register them with metadata
            from app.plugins.example.models.example_models import (
                PluginExampleUser, PluginExamplePost, PluginExampleSetting
            )
            
            # Get plugin base and create tables
            base = self.get_plugin_base()
            session_factory = self.get_plugin_session()
            
            with session_factory() as db:
                base.metadata.create_all(bind=db.bind)
                db.commit()
                logger.info("Created example plugin tables")
                
                # Insert some initial data if tables are empty
                self._insert_initial_data(db)
                
        except Exception as e:
            logger.error(f"Error creating example plugin tables: {e}")
    
    def _insert_initial_data(self, db: Session):
        """Insert initial test data"""
        try:
            from app.plugins.example.models.example_models import (
                PluginExampleUser, PluginExamplePost, PluginExampleSetting
            )
            
            # Check if data already exists
            if db.query(PluginExampleUser).first():
                return
            
            # Create initial user
            user = PluginExampleUser(
                username="admin",
                email="admin@example.com",
                full_name="Administrator",
                is_active=True
            )
            db.add(user)
            db.flush()  # Get the ID
            
            # Create initial post
            post = PluginExamplePost(
                title="Welcome to Plugin Database System",
                content="This is an example post created by the example plugin.",
                is_published=True,
                author_id=user.id
            )
            db.add(post)
            
            # Create initial settings
            settings = [
                PluginExampleSetting(
                    key="max_posts_per_user",
                    value="100",
                    description="Maximum number of posts per user"
                ),
                PluginExampleSetting(
                    key="enable_email_notifications",
                    value="true",
                    description="Enable email notifications for new posts"
                )
            ]
            
            for setting in settings:
                db.add(setting)
            
            db.commit()
            logger.info("Inserted initial data for example plugin")
            
        except Exception as e:
            logger.error(f"Error inserting initial data: {e}")
            db.rollback()
    
    def get_state(self) -> bool:
        """Get plugin running state"""
        return self._enabled
    
    def stop_service(self):
        """Stop plugin service"""
        self._enabled = False
        logger.info("Example plugin service stopped")
    
    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        """Get plugin commands"""
        return []
    
    def get_api(self) -> List[Dict[str, Any]]:
        """Get plugin API endpoints"""
        return [
            {
                "path": "/example/users",
                "endpoint": self.get_users,
                "methods": ["GET"],
                "summary": "Get all users",
                "tags": ["Example Plugin"]
            },
            {
                "path": "/example/posts",
                "endpoint": self.get_posts,
                "methods": ["GET"],
                "summary": "Get all posts",
                "tags": ["Example Plugin"]
            },
            {
                "path": "/example/settings",
                "endpoint": self.get_settings,
                "methods": ["GET"],
                "summary": "Get plugin settings",
                "tags": ["Example Plugin"]
            },
            {
                "path": "/example/info",
                "endpoint": self.get_plugin_info,
                "methods": ["GET"],
                "summary": "Get plugin database info",
                "tags": ["Example Plugin"]
            }
        ]
    
    def get_page(self) -> List[Dict[str, Any]]:
        """Get plugin page configuration"""
        return [{
            "component": "div",
            "text": "Example Plugin with Database",
            "props": {
                "class": "text-center"
            }
        }]
    
    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """Get plugin form configuration"""
        return [
            {
                'component': 'VRow',
                'content': [
                    {
                        'component': 'VCol',
                        'props': {
                            'cols': 12,
                            'md': 6
                        },
                        'content': [
                            {
                                'component': 'VSwitch',
                                'props': {
                                    'model': 'enabled',
                                    'label': '启用插件',
                                }
                            }
                        ]
                    }
                ]
            },
            {
                'component': 'VRow',
                'content': [
                    {
                        'component': 'VCol',
                        'props': {
                            'cols': 12
                        },
                        'content': [
                            {
                                'component': 'VAlert',
                                'props': {
                                    'type': 'info',
                                    'variant': 'tonal',
                                    'text': '这是一个演示插件数据库系统的示例插件。启用后将创建示例数据表并插入测试数据。'
                                }
                            }
                        ]
                    }
                ]
            }
        ], {
            "enabled": False
        }
    
    # API endpoints
    @with_plugin_db('example')
    def get_users(self, db: Session) -> Dict[str, Any]:
        """Get all users from plugin database"""
        try:
            from app.plugins.example.models.example_models import PluginExampleUser
            
            users = db.query(PluginExampleUser).all()
            return {
                "success": True,
                "data": [
                    {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "full_name": user.full_name,
                        "is_active": user.is_active,
                        "created_at": user.created_at.isoformat() if user.created_at else None,
                        "post_count": len(user.posts) if user.posts else 0
                    }
                    for user in users
                ]
            }
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            return {"success": False, "error": str(e)}
    
    @with_plugin_db('example')
    def get_posts(self, db: Session) -> Dict[str, Any]:
        """Get all posts from plugin database"""
        try:
            from app.plugins.example.models.example_models import PluginExamplePost
            
            posts = db.query(PluginExamplePost).all()
            return {
                "success": True,
                "data": [
                    {
                        "id": post.id,
                        "title": post.title,
                        "content": post.content,
                        "is_published": post.is_published,
                        "author_username": post.author.username if post.author else None,
                        "created_at": post.created_at.isoformat() if post.created_at else None
                    }
                    for post in posts
                ]
            }
        except Exception as e:
            logger.error(f"Error getting posts: {e}")
            return {"success": False, "error": str(e)}
    
    @with_plugin_db('example')
    def get_settings(self, db: Session) -> Dict[str, Any]:
        """Get plugin settings from database"""
        try:
            from app.plugins.example.models.example_models import PluginExampleSetting
            
            settings = db.query(PluginExampleSetting).all()
            return {
                "success": True,
                "data": [
                    {
                        "key": setting.key,
                        "value": setting.value,
                        "description": setting.description
                    }
                    for setting in settings
                ]
            }
        except Exception as e:
            logger.error(f"Error getting settings: {e}")
            return {"success": False, "error": str(e)}
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Get plugin database information"""
        try:
            # Get database info
            db_info = self.get_plugin_database_info()
            
            # Get validation results
            validation = self.validate_plugin_database()
            
            return {
                "success": True,
                "data": {
                    "database_info": db_info,
                    "validation": validation
                }
            }
        except Exception as e:
            logger.error(f"Error getting plugin info: {e}")
            return {"success": False, "error": str(e)}