# master_processor.py

import os
import csv
import logging
from logging.handlers import RotatingFileHandler
import subprocess
from multiprocessing import Semaphore
from tqdm import tqdm
import glob
import signal
import sys
import time

# =======================
# Logging Setup
# =======================

# Create a logger
logger = logging.getLogger("MasterProcessor")
logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed logs

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # INFO level for console

# Create rotating file handler
file_handler = RotatingFileHandler(
    "master_processor.log",
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5,  # Keep up to 5 backup log files
)
file_handler.setLevel(logging.DEBUG)  # DEBUG level for file

# Define log formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# Add formatter to handlers
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# =======================
# Global Variables for Graceful Shutdown
# =======================

active_subprocesses = []
semaphore = None
individual_dir = None
master_csv = None

# =======================
# Graceful Shutdown Handler
# =======================


def signal_handler(sig, frame):
    logger.warning("Interrupt received. Terminating gracefully...")
    # Terminate all active subprocesses
    for proc, path in active_subprocesses[:]:
        proc.terminate()
        logger.info(f"Terminated subprocess for {path}")
    # Concatenate any processed CSVs
    concatenate_individual_csvs(individual_dir, master_csv)
    logger.info("Consolidated results before shutdown.")
    sys.exit(0)


# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# =======================
# Function to Process a Single APK
# =======================


def process_apk(apk_path, individual_dir):
    """
    Process a single APK by invoking the individual processing script.
    Returns the subprocess.Popen object if successful, else None.
    """
    try:
        apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        output_csv = os.path.join(individual_dir, f"{apk_name}.csv")

        # Determine the path to process_single_apk.py
        script_dir = os.path.dirname(os.path.abspath(__file__))
        process_script = os.path.join(script_dir, "process_single_apk.py")

        if not os.path.exists(process_script):
            logger.error(f"process_single_apk.py not found at {process_script}")
            return None

        cmd = ["python", process_script, apk_path, output_csv]
        logger.debug(f"Executing command: {' '.join(cmd)}")

        # Start the subprocess
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return proc
    except Exception as e:
        logger.error(f"Failed to spawn subprocess for {apk_path}: {e}")
        return None


# =======================
# Function to Concatenate CSVs
# =======================


def concatenate_individual_csvs(individual_dir, master_csv):
    """
    Concatenate all individual CSV files into a master CSV and delete individual files.
    """
    try:
        csv_files = glob.glob(os.path.join(individual_dir, "*.csv"))
        if not csv_files:
            logger.error(f"No individual CSV files found in {individual_dir}.")
            return

        with open(master_csv, "a", newline="", encoding="utf-8") as master_file:
            fieldnames = [
                "apk_path",
                "label",
                "complexity_score",
                "permissions",
                "permissions_count",
                "native_code",
                "native_code_count",
                "obfuscated_strings_count",
                "dynamic_code_use_count",
                "apk_entropy",
                "code_length",
                "file_size_mb",
                "file_hash",
            ]
            writer = csv.DictWriter(master_file, fieldnames=fieldnames)
            # Write header if master CSV is empty
            if os.path.getsize(master_csv) == 0:
                writer.writeheader()

            for csv_file in tqdm(csv_files, desc="Concatenating CSV files"):
                try:
                    with open(
                        csv_file, "r", newline="", encoding="utf-8"
                    ) as individual_file:
                        reader = csv.DictReader(individual_file)
                        for row in reader:
                            writer.writerow(row)
                    # Delete individual CSV after successful concatenation
                    os.remove(csv_file)
                    logger.debug(f"Deleted individual CSV: {csv_file}")
                except Exception as e:
                    logger.error(
                        f"Error reading or deleting individual CSV {csv_file}: {e}"
                    )

        logger.info(
            f"All individual CSV files have been concatenated into {master_csv}"
        )
    except Exception as e:
        logger.error(f"Error during concatenation: {e}")


# =======================
# Function to List and Verify Discovered APKs
# =======================


def list_discovered_apks(base_path, processed_apks):
    """
    List all APKs found in the base_path that haven't been processed yet.
    """
    apks = []
    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(".apk"):
                apk_path = os.path.join(root, file)
                if apk_path not in processed_apks:
                    apks.append(apk_path)
    logger.info(f"Total APKs found: {len(apks)}")
    for apk in apks[:10]:  # List first 10 APKs for verification
        logger.info(f"Discovered APK: {apk}")
    return apks


# =======================
# Main Processing Function
# =======================


def main():
    global individual_dir, master_csv, semaphore

    base_path = "./KronoDroid_Real_Malware_03"  # Update this path as needed
    individual_dir = "individual_outputs"
    master_csv = "analysis_results_master.csv"
    max_concurrent_processes = 2  # Adjust based on your system's capability

    # Create individual output directory if it doesn't exist
    if not os.path.exists(individual_dir):
        os.makedirs(individual_dir)
        logger.info(f"Created directory for individual outputs: {individual_dir}")

    # Read already processed APKs to avoid reprocessing
    processed_apks = set()
    if os.path.exists(master_csv):
        try:
            with open(master_csv, "r", newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    processed_apks.add(row["apk_path"])
            logger.info(
                f"Found {len(processed_apks)} already processed APKs in {master_csv}."
            )
        except Exception as e:
            logger.error(f"Error reading existing master CSV file: {e}")

    # List and verify discovered APKs
    apks = list_discovered_apks(base_path, processed_apks)
    if not apks:
        logger.warning("No new APKs found to process. Exiting script.")
        return

    # Initialize semaphore to limit concurrent subprocesses
    semaphore = Semaphore(max_concurrent_processes)

    # Initialize progress bar
    pbar = tqdm(total=len(apks), desc="Processing APKs")

    for apk_path in apks:
        semaphore.acquire()
        proc = process_apk(apk_path, individual_dir)
        if proc:
            active_subprocesses.append((proc, apk_path))
        else:
            # If subprocess failed to start, update progress bar and release semaphore
            pbar.update(1)
            semaphore.release()

        # Check if any subprocess has finished
        for active_proc, path in active_subprocesses[:]:
            retcode = active_proc.poll()
            if retcode is not None:
                stdout, stderr = active_proc.communicate()
                if retcode == 0:
                    logger.info(f"Successfully processed {path}")
                    logger.debug(f"Subprocess output for {path}:\n{stdout}")
                else:
                    logger.error(f"Error processing {path}: {stderr.strip()}")
                active_subprocesses.remove((active_proc, path))
                pbar.update(1)
                semaphore.release()

    # After spawning all APKs, wait for remaining subprocesses to finish
    while active_subprocesses:
        for active_proc, path in active_subprocesses[:]:
            retcode = active_proc.poll()
            if retcode is not None:
                stdout, stderr = active_proc.communicate()
                if retcode == 0:
                    logger.info(f"Successfully processed {path}")
                    logger.debug(f"Subprocess output for {path}:\n{stdout}")
                else:
                    logger.error(f"Error processing {path}: {stderr.strip()}")
                active_subprocesses.remove((active_proc, path))
                pbar.update(1)
                semaphore.release()
        time.sleep(1)  # Avoid busy waiting

    pbar.close()

    # Concatenate all individual CSVs into master CSV
    concatenate_individual_csvs(individual_dir, master_csv)

    logger.info("All APKs have been processed and results have been consolidated.")


if __name__ == "__main__":
    main()
