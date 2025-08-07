from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
from datetime import datetime, timedelta
import json
import os
from webapp import app, scan_network, port_scan, os_detect, dns_audit, capture_packets, run_auto_vuln_scan, run_custom_vuln_scan, firewall_test_all_rules, map_network_topology, check_for_intrusion, generate_pdf, save_report

# Configure the scheduler
jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///scheduled_jobs.db')
}

executors = {
    'default': ThreadPoolExecutor(20),
}

job_defaults = {
    'coalesce': False,
    'max_instances': 3
}

scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults)

def init_scheduler():
    """Initialize the scheduler"""
    try:
        if not scheduler.running:
            # Ensure the database directory exists
            os.makedirs(os.path.dirname('scheduled_jobs.db') or '.', exist_ok=True)
            
            # Start the scheduler
            scheduler.start()
            print("✓ Scheduler started successfully")
            
            # Test database connection
            try:
                jobs = scheduler.get_jobs()
                print(f"✓ Database connection successful. Found {len(jobs)} existing jobs.")
            except Exception as db_error:
                print(f"⚠ Database connection warning: {db_error}")
                print("   You may need to run: python setup_database.py")
                
    except Exception as e:
        print(f"✗ Failed to start scheduler: {e}")
        print("   Please run: python setup_database.py")
        raise

def shutdown_scheduler():
    """Shutdown the scheduler"""
    if scheduler.running:
        scheduler.shutdown()
        print("Scheduler shutdown")

# Task execution functions
def execute_network_scan(job_id, subnet, user_email=None):
    """Execute network scan task"""
    try:
        with app.app_context():
            result = scan_network(subnet)
            save_scheduled_result(job_id, "network_scan", result, user_email)
            print(f"Network scan completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "network_scan", {"error": str(e)}, user_email)
        print(f"Network scan failed for job {job_id}: {e}")

def execute_port_scan(job_id, ip, ports, user_email=None):
    """Execute port scan task"""
    try:
        with app.app_context():
            result = port_scan(ip, ports)
            save_scheduled_result(job_id, "port_scan", result, user_email)
            print(f"Port scan completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "port_scan", {"error": str(e)}, user_email)
        print(f"Port scan failed for job {job_id}: {e}")

def execute_os_detection(job_id, ip, user_email=None):
    """Execute OS detection task"""
    try:
        with app.app_context():
            result = os_detect(ip)
            save_scheduled_result(job_id, "os_detection", result, user_email)
            print(f"OS detection completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "os_detection", {"error": str(e)}, user_email)
        print(f"OS detection failed for job {job_id}: {e}")

def execute_dns_audit(job_id, domain, user_email=None):
    """Execute DNS audit task"""
    try:
        with app.app_context():
            result = dns_audit(domain)
            save_scheduled_result(job_id, "dns_audit", result, user_email)
            print(f"DNS audit completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "dns_audit", {"error": str(e)}, user_email)
        print(f"DNS audit failed for job {job_id}: {e}")

def execute_packet_capture(job_id, count, user_email=None):
    """Execute packet capture task"""
    try:
        with app.app_context():
            result = capture_packets(count)
            save_scheduled_result(job_id, "packet_capture", result, user_email)
            print(f"Packet capture completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "packet_capture", {"error": str(e)}, user_email)
        print(f"Packet capture failed for job {job_id}: {e}")

def execute_vulnerability_scan(job_id, ip, scan_mode, keyword, user_email=None):
    """Execute vulnerability scan task"""
    try:
        with app.app_context():
            if scan_mode == 'auto':
                result, duration = run_auto_vuln_scan(ip)
            else:
                result = run_custom_vuln_scan(ip, keyword)
            save_scheduled_result(job_id, "vulnerability_scan", result, user_email)
            print(f"Vulnerability scan completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "vulnerability_scan", {"error": str(e)}, user_email)
        print(f"Vulnerability scan failed for job {job_id}: {e}")

def execute_firewall_test(job_id, user_email=None):
    """Execute firewall test task"""
    try:
        with app.app_context():
            result, duration = firewall_test_all_rules()
            save_scheduled_result(job_id, "firewall_test", result, user_email)
            print(f"Firewall test completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "firewall_test", {"error": str(e)}, user_email)
        print(f"Firewall test failed for job {job_id}: {e}")

def execute_network_topology(job_id, subnet, user_email=None):
    """Execute network topology mapping task"""
    try:
        with app.app_context():
            html_content, duration = map_network_topology(subnet)
            result = {"html_content": html_content, "duration": duration}
            save_scheduled_result(job_id, "network_topology", result, user_email)
        print(f"Network topology completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "network_topology", {"error": str(e)}, user_email)
        print(f"Network topology failed for job {job_id}: {e}")

def execute_intrusion_detection(job_id, subnet, genuine_hosts, user_email=None):
    """Execute intrusion detection task"""
    try:
        with app.app_context():
            scanned_hosts = scan_network(subnet)
            intrusions, duration = check_for_intrusion(scanned_hosts['hosts'], genuine_hosts)
            result = {"intrusions": intrusions, "duration": duration}
            save_scheduled_result(job_id, "intrusion_detection", result, user_email)
            print(f"Intrusion detection completed for job {job_id}")
    except Exception as e:
        save_scheduled_result(job_id, "intrusion_detection", {"error": str(e)}, user_email)
        print(f"Intrusion detection failed for job {job_id}: {e}")

def save_scheduled_result(job_id, task_type, result, user_email=None):
    """Save the result of a scheduled task"""
    try:
        # Create scheduled_results directory if it doesn't exist
        os.makedirs('scheduled_results', exist_ok=True)
        
        # Save result to file
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f'scheduled_results/job_{job_id}_{task_type}_{timestamp}.json'
        
        result_data = {
            'job_id': job_id,
            'task_type': task_type,
            'timestamp': timestamp,
            'result': result,
            'user_email': user_email
        }
        
        with open(filename, 'w') as f:
            json.dump(result_data, f, indent=2)
        
        # Generate PDF report
        try:
            pdf_buffer, duration = generate_pdf(result, f"Scheduled {task_type.replace('_', ' ').title()} Report")
            pdf_filename = f'scheduled_results/job_{job_id}_{task_type}_{timestamp}.pdf'
            with open(pdf_filename, 'wb') as f:
                f.write(pdf_buffer.getvalue())
        except Exception as e:
            print(f"Failed to generate PDF for job {job_id}: {e}")
            
    except Exception as e:
        print(f"Failed to save result for job {job_id}: {e}")

def schedule_task(task_type, schedule_time, **kwargs):
    """Schedule a task for execution"""
    try:
        # Generate unique job ID
        job_id = f"{task_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Map task types to execution functions
        task_functions = {
            'network_scan': execute_network_scan,
            'port_scan': execute_port_scan,
            'os_detection': execute_os_detection,
            'dns_audit': execute_dns_audit,
            'packet_capture': execute_packet_capture,
            'vulnerability_scan': execute_vulnerability_scan,
            'firewall_test': execute_firewall_test,
            'network_topology': execute_network_topology,
            'intrusion_detection': execute_intrusion_detection
        }
        
        if task_type not in task_functions:
            raise ValueError(f"Unknown task type: {task_type}")
        
        # Add job to scheduler
        scheduler.add_job(
            func=task_functions[task_type],
            trigger='date',
            run_date=schedule_time,
            args=[job_id] + list(kwargs.values()),
            id=job_id,
            name=f"Scheduled {task_type.replace('_', ' ').title()}",
            replace_existing=True
        )
        
        return job_id
        
    except Exception as e:
        print(f"Failed to schedule task: {e}")
        return None

def get_scheduled_jobs():
    """Get all scheduled jobs"""
    try:
        jobs = []
        for job in scheduler.get_jobs():
            jobs.append({
                'id': job.id,
                'name': job.name,
                'next_run_time': job.next_run_time.isoformat() if job.next_run_time else None,
                'trigger': str(job.trigger)
            })
        return jobs
    except Exception as e:
        print(f"Failed to get scheduled jobs: {e}")
        return []

def remove_scheduled_job(job_id):
    """Remove a scheduled job"""
    try:
        scheduler.remove_job(job_id)
        return True
    except Exception as e:
        print(f"Failed to remove job {job_id}: {e}")
        return False

def get_job_results(job_id=None):
    """Get results of scheduled jobs"""
    try:
        results = []
        results_dir = 'scheduled_results'
        
        if not os.path.exists(results_dir):
            return results
        
        for filename in os.listdir(results_dir):
            if filename.endswith('.json') and (job_id is None or job_id in filename):
                filepath = os.path.join(results_dir, filename)
                with open(filepath, 'r') as f:
                    result_data = json.load(f)
                    results.append(result_data)
        
        # Sort by timestamp (newest first)
        results.sort(key=lambda x: x['timestamp'], reverse=True)
        return results
        
    except Exception as e:
        print(f"Failed to get job results: {e}")
        return []
