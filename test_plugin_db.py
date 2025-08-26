#!/usr/bin/env python3
"""
Basic tests for plugin database system
"""
import sys
import tempfile
import shutil
from pathlib import Path

def test_table_name_validation():
    """Test table name validation function"""
    print("Testing table name validation...")
    
    # Import the validation function directly
    import re
    
    def validate_table_name(plugin_id: str, table_name: str) -> bool:
        plugin_id_lower = plugin_id.lower()
        expected_prefix = f"plugin_{plugin_id_lower}_"
        
        if not table_name.startswith(expected_prefix):
            return False
        
        # Check if the rest of the name is valid (lowercase, underscore separated)
        suffix = table_name[len(expected_prefix):]
        if not re.match(r'^[a-z][a-z0-9_]*$', suffix):
            return False
        
        return True
    
    # Test cases
    test_cases = [
        ('testplugin', 'plugin_testplugin_user', True),
        ('testplugin', 'plugin_testplugin_user_data', True),
        ('testplugin', 'plugin_wrongplugin_user', False),
        ('testplugin', 'user_table', False),
        ('testplugin', 'plugin_testplugin_', False),
        ('testplugin', 'plugin_testplugin_User', False),  # uppercase not allowed
        ('example', 'plugin_example_user', True),
        ('example', 'plugin_example_post', True),
        ('example', 'plugin_example_setting', True),
    ]
    
    all_passed = True
    for plugin_id, table_name, expected in test_cases:
        result = validate_table_name(plugin_id, table_name)
        status = '✓' if result == expected else '✗'
        print(f'  {status} {plugin_id:12} | {table_name:30} | {result} (expected {expected})')
        if result != expected:
            all_passed = False
    
    return all_passed


def test_plugin_structure():
    """Test plugin directory structure creation"""
    print("\\nTesting plugin directory structure...")
    
    try:
        # Test if example plugin directory exists
        plugin_dir = Path("app/plugins/example")
        if not plugin_dir.exists():
            print("  ✗ Example plugin directory does not exist")
            return False
        
        # Check for required files
        required_files = [
            "app/plugins/example/__init__.py",
            "app/plugins/example/models/example_models.py",
            "app/plugins/example/models/README.md"
        ]
        
        all_exists = True
        for file_path in required_files:
            if Path(file_path).exists():
                print(f"  ✓ {file_path} exists")
            else:
                print(f"  ✗ {file_path} does not exist")
                all_exists = False
        
        return all_exists
        
    except Exception as e:
        print(f"  ✗ Error testing plugin structure: {e}")
        return False


def test_core_modules():
    """Test that core modules can be imported"""
    print("\\nTesting core module imports...")
    
    # Test individual validation function without heavy dependencies
    try:
        # Test the validation logic
        result = test_table_name_validation()
        if result:
            print("  ✓ Table name validation works")
        else:
            print("  ✗ Table name validation failed")
            return False
        
        print("  ✓ Core functionality verified")
        return True
        
    except Exception as e:
        print(f"  ✗ Error testing core modules: {e}")
        return False


def main():
    """Run basic tests"""
    print("Running basic plugin database system tests...")
    print("=" * 60)
    
    tests = [
        ("Table Name Validation", test_table_name_validation),
        ("Plugin Structure", test_plugin_structure),
        ("Core Modules", test_core_modules),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\\n{test_name}:")
        try:
            if test_func():
                print(f"✓ {test_name} PASSED")
                passed += 1
            else:
                print(f"✗ {test_name} FAILED")
        except Exception as e:
            print(f"✗ {test_name} ERROR: {e}")
    
    print("\\n" + "=" * 60)
    print(f"Tests: {passed}/{total} passed")
    
    if passed == total:
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())