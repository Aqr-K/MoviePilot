"""
Example Plugin Database Models

This module demonstrates how to create database models for plugins.
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.core.plugin_db_utils import PluginModel
from app.core.plugin_db import plugin_db_manager

# Get plugin-specific Base class
ExampleBase = plugin_db_manager.get_plugin_base('example')


class PluginExampleUser(ExampleBase, PluginModel):
    """Example user model for the example plugin"""
    
    # Table name must follow pattern: plugin_{plugin_id}_{model_name}
    __tablename__ = 'plugin_example_user'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False, unique=True, index=True)
    email = Column(String(100), nullable=True, index=True)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationship to posts
    posts = relationship("PluginExamplePost", back_populates="author", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<PluginExampleUser(username='{self.username}', email='{self.email}')>"


class PluginExamplePost(ExampleBase, PluginModel):
    """Example post model for the example plugin"""
    
    # Table name must follow pattern: plugin_{plugin_id}_{model_name}
    __tablename__ = 'plugin_example_post'
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False, index=True)
    content = Column(Text, nullable=True)
    is_published = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Foreign key to user
    author_id = Column(Integer, ForeignKey('plugin_example_user.id'), nullable=False, index=True)
    
    # Relationship to author
    author = relationship("PluginExampleUser", back_populates="posts")
    
    def __repr__(self):
        return f"<PluginExamplePost(title='{self.title}', author_id={self.author_id})>"


class PluginExampleSetting(ExampleBase, PluginModel):
    """Example settings model for the example plugin"""
    
    # Table name must follow pattern: plugin_{plugin_id}_{model_name}
    __tablename__ = 'plugin_example_setting'
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), nullable=False, unique=True, index=True)
    value = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<PluginExampleSetting(key='{self.key}', value='{self.value}')>"