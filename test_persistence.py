import subprocess
import time
import os
import signal
import sys

SERVER_BIN = "./nvram_db"
CLIENT_BIN = "./nvram_client"
DB_FILE = "nvram_disk"

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result

def start_server():
    print("Starting server...")
    # Start server in background
    process = subprocess.Popen([SERVER_BIN], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1) # Wait for server to start
    if process.poll() is not None:
        print("Server failed to start")
        print(process.stderr.read())
        sys.exit(1)
    return process

def stop_server(process):
    print("Stopping server...")
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        print("Server did not exit gracefully, killing...")
        process.kill()

def clean_env():
    print("Cleaning environment...")
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    run_command("make clean")
    run_command("make")

def test_persistence():
    clean_env()

    # Phase 1: Create and Insert
    print("\n--- Phase 1: Create Table and Insert Row ---")
    server_proc = start_server()
    
    # Inputs for Phase 1:
    # 1. Create Table (1) -> test_persist
    # 2. Use Table (2) -> test_persist
    # 3. Begin Transaction (3)
    # 4. Insert Row (6) -> 10 -> persistent_data
    # 5. Commit (4)
    # 6. Exit (10)
    input_phase_1 = "1\ntest_persist\n2\ntest_persist\n3\n6\n10\npersistent_data\n4\n10\n"
    
    client_proc = subprocess.run([CLIENT_BIN], input=input_phase_1, capture_output=True, text=True)
    print("Client Output Phase 1:\n", client_proc.stdout)
    
    if "Row inserted" not in client_proc.stdout:
        print("FAILED: Row insertion failed")
        stop_server(server_proc)
        sys.exit(1)

    stop_server(server_proc)
    time.sleep(1) # Ensure file flush

    # Phase 2: Verify Persistence
    print("\n--- Phase 2: Verify Persistence ---")
    server_proc = start_server()

    # Inputs for Phase 2:
    # 1. Use Table (2) -> test_persist
    # 2. Begin Transaction (3)
    # 3. Get Row (7) -> 10
    # 4. Commit (4)
    # 5. Exit (10)
    input_phase_2 = "2\ntest_persist\n3\n7\n10\n4\n10\n"
    
    client_proc = subprocess.run([CLIENT_BIN], input=input_phase_2, capture_output=True, text=True)
    print("Client Output Phase 2:\n", client_proc.stdout)

    stop_server(server_proc)

    if "Row 10: persistent_data" in client_proc.stdout:
        print("\nSUCCESS: Data persisted correctly!")
    else:
        print("\nFAILED: Data did not persist.")
        sys.exit(1)

if __name__ == "__main__":
    test_persistence()
