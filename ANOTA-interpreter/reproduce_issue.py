import multiprocessing.resource_tracker as rt
import time
import os

def reproduce():
    print(f"Main process: {os.getpid()}")
    
    # Ensure tracker is running
    rt.ensure_running()
    
    # We need to know a valid rtype. 
    # On Linux, 'shared_memory' is usually available if _posixshmem is.
    # The error log showed /psm_... which is shared memory.
    rtype = 'shared_memory'
    name = '/psm_test_repro'
    
    print(f"Sending UNREGISTER for {name} (not registered)...")
    
    # This should cause the tracker to crash with KeyError if the bug exists
    try:
        rt.unregister(name, rtype)
    except Exception as e:
        print(f"Caught exception in client: {e}")
        
    # Give the tracker a moment to process and potentially crash
    time.sleep(1)
    
    # Check if tracker is still alive
    if rt._resource_tracker._check_alive():
        print("Tracker is still alive.")
    else:
        print("Tracker died (reproduced!)")

if __name__ == "__main__":
    reproduce()
