#!/usr/bin/env python3
"""
Database setup script for the Network Auditing Task Scheduler
This script initializes the SQLite database used by APScheduler to store scheduled jobs.
"""
import os
#from sqlalchemy import create_engine, text, SQLAlchemyJobStore 
from sqlalchemy import create_engine, text
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
  # Make sure this import is at the top

def setup_database():
    """Set up the SQLite database for APScheduler job store"""
    try:
        db_url = 'sqlite:///scheduled_jobs.db'
        engine = create_engine(db_url)

        jobstore = SQLAlchemyJobStore(url=db_url)
        
        # Create a temporary scheduler to initialize the database tables
        from apscheduler.schedulers.background import BackgroundScheduler
        temp_scheduler = BackgroundScheduler()
        temp_scheduler.add_jobstore(jobstore)
        temp_scheduler.start()
        temp_scheduler.shutdown()

        print("✓ Database setup completed successfully!")
        print(f"✓ Database file: {os.path.abspath('scheduled_jobs.db')}")

        # Test the connection
        with engine.connect() as conn:
            result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            tables = [row[0] for row in result]
            print(f"✓ Created tables: {', '.join(tables)}")

        return True

    except Exception as e:
        print(f"✗ Database setup failed: {e}")
        return False
