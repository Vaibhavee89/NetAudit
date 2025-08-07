#!/usr/bin/env python3
"""
Test script for the scheduler functionality
"""

import sys
import os
from datetime import datetime, timedelta

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_scheduler():
    """Test the scheduler functionality"""
    try:
        from scheduler import init_scheduler, schedule_task, get_scheduled_jobs, remove_scheduled_job
        
        print("Testing scheduler functionality...")
        
        # Initialize scheduler
        init_scheduler()
        print("✓ Scheduler initialized")
        
        # Test scheduling a task
        schedule_time = datetime.now() + timedelta(minutes=2)  # Schedule 2 minutes from now
        job_id = schedule_task('dns_audit', schedule_time, domain='google.com')
        
        if job_id:
            print(f"✓ Task scheduled successfully with ID: {job_id}")
        else:
            print("✗ Failed to schedule task")
            return False
        
        # Test getting scheduled jobs
        jobs = get_scheduled_jobs()
        print(f"✓ Found {len(jobs)} scheduled jobs")
        
        # Test removing the scheduled job
        if remove_scheduled_job(job_id):
            print("✓ Job removed successfully")
        else:
            print("✗ Failed to remove job")
            return False
        
        print("✓ All scheduler tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Scheduler test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_scheduler()
    sys.exit(0 if success else 1)
