"""
SecureAudit Pro - Celery Background Tasks & Async Execution Runner
Handles asynchronous scanning jobs and report generation.
"""

import threading
import logging
from celery import shared_task
from security_engine.dispatcher import ScanDispatcher

logger = logging.getLogger(__name__)


@shared_task(bind=True, name="tasks.run_scan_job")
def run_scan_job(self, scan_job_id: str):
    """Celery task entrypoint for background security scanning."""
    try:
        dispatcher = ScanDispatcher(scan_job_id)
        result = dispatcher.run()
        return result
    except Exception as e:
        logger.error(f"Error executing scan job {scan_job_id}: {e}")
        return {"status": "failed", "error": str(e)}


def is_redis_available() -> bool:
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", 6379), timeout=0.3)
        s.close()
        return True
    except Exception:
        return False


def dispatch_scan_async(scan_job_id: str):
    """
    Triggers scan execution. Uses Celery delay() if Redis broker is available;
    otherwise immediately launches an async background daemon thread without blocking timeouts.
    """
    if is_redis_available():
        try:
            run_scan_job.delay(str(scan_job_id))
            logger.info(f"Queued scan {scan_job_id} via Celery worker.")
            return
        except Exception as e:
            logger.warning(f"Celery queueing failed ({e}). Falling back to thread.")

    # Instant background Thread runner
    def thread_target():
        try:
            dispatcher = ScanDispatcher(str(scan_job_id))
            dispatcher.run()
        except Exception as ex:
            logger.error(f"Thread scan runner error: {ex}")

    t = threading.Thread(target=thread_target, daemon=True)
    t.start()
