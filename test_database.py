#!/usr/bin/env python3
"""
Test script to verify database setup and scheduler functionality
"""

import os
import sys
from datetime import datetime, timedelta

def test_database_setup():
    """Test if the database is properly set up"""
    try:
        # Check if database file exists
        if not os.path.exists('scheduled_jobs.db'):
            print("✗ Database file does not exist")
            return False
        
        print("✓ Database file exists")
        
        # Test SQLAlchemy connection
        from sqlalchemy import create_engine, text
        engine = create_engine('sqlite:///scheduled_jobs.db')
        
        with engine.connect() as conn:
            result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            tables = [row[0] for row in result]
            
            if 'apscheduler_jobs' in tables:
                print("✓ APScheduler tables exist")
                return True
            else:
                print(f"✗ APScheduler tables missing. Found tables: {tables}")
                return False
                
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        return False

def test_scheduler_import():
    """Test if scheduler can be imported"""
    try:
        from scheduler import init_scheduler, shutdown_scheduler
        print("✓ Scheduler module imported successfully")
        return True
    except Exception as e:
        print(f"✗ Scheduler import failed: {e}")
        return False

def test_scheduler_initialization():
    """Test scheduler initialization"""
    try:
        from scheduler import init_scheduler, shutdown_scheduler
        
        # Initialize scheduler
        init_scheduler()
        print("✓ Scheduler initialized successfully")
        
        # Shutdown scheduler
        shutdown_scheduler()
        print("✓ Scheduler shutdown successfully")
        
        return True
    except Exception as e:
        print(f"✗ Scheduler initialization failed: {e}")
        return False

if __name__ == "__main__":
    print("Database and Scheduler Test")
    print("=" * 30)
    
    tests = [
        ("Database Setup", test_database_setup),
        ("Scheduler Import", test_scheduler_import),
        ("Scheduler Initialization", test_scheduler_initialization)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\nTesting: {test_name}")
        print("-" * 20)
        if test_func():
            passed += 1
            print(f"✓ {test_name} passed")
        else:
            print(f"✗ {test_name} failed")
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! Your database and scheduler are ready.")
        print("You can now run: python webapp.py")
    else:
        print("✗ Some tests failed. Please run: python setup_database.py")
        sys.exit(1)
