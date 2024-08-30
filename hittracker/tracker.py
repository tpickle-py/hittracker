import argparse
import importlib
import multiprocessing
import os
import pkgutil
import time
from datetime import datetime
from multiprocessing import Manager

from utils import (
    compile_regex_file,
    get_date_from_folder,
    get_file_creation_date,
    order_folders_by_oldest,
    parse_folder,
    normalize_path,
)

from reports import export_to_csv, generate_pdf_report

DB_FILE = os.environ.get("DB_FILE_HT", "firewall_policies.db")


class FirewallPolicyTracker:
    def __init__(self, rxp):
        from db import DatabaseManager

        db_file = os.environ.get("DB_FILE", "firewall_policies.db")
        self.db = DatabaseManager(db_name=db_file)
        self.plugins = {}
        self.load_plugins()
        self.rxp = rxp

    def load_plugins(self):
        import plugins

        for _, plugin_name, _ in pkgutil.iter_modules(plugins.__path__):
            plugin = importlib.import_module(f"plugins.{plugin_name}")
            plugin_class = getattr(plugin, f"{plugin_name.capitalize()}Plugin")
            self.plugins[plugin_name] = plugin_class()

    def generate_report(self, days_threshold):
        unused_policies = self.db.get_unused_policies(days_threshold)
        report = []
        for (
            firewall_name,
            device_type,
            policy_name,
            last_zero_hit,
            first_zero_hit,
        ) in unused_policies:
            if type(last_zero_hit) is not str:
                last_zero_hit = str(last_zero_hit)
            if type(first_zero_hit) is not str:
                first_zero_hit = str(first_zero_hit)
            captures = self.db.get_policy_history(
                firewall_name, device_type, policy_name
            )
            days_since_last_import = (
                datetime.now().date()
                - datetime.strptime(last_zero_hit, "%Y-%m-%d").date()
            ).days
            total_days_unused = (
                datetime.now().date()
                - datetime.strptime(first_zero_hit, "%Y-%m-%d").date()
            ).days
            report.append(
                {
                    "Firewall": firewall_name,
                    "Policy": policy_name,
                    "Last Seen Unused": last_zero_hit,
                    "First Seen Unused": first_zero_hit,
                    "Days Since Last Import": days_since_last_import,
                    "Total Days Unused": total_days_unused,
                    "Captures": captures,
                    "Status": "Flagged for Removal",
                }
            )
        return report


def param_parser():
    parser = argparse.ArgumentParser(description="Firewall Policy Tracker")
    parser.add_argument("-f", "--folder", help="Folder to process", required=True)
    parser.add_argument(
        "-d", "--days", help="Days threshold for removal", type=int, default=90
    )
    parser.add_argument(
        "-r",
        "--rxp",
        help="Regex file for filtering, file stored in current folder or path to file",
        default="filter.rxp",
        required=False,
        dest="rxp",
    )
    parser.add_argument(
        "--csv", help="Export to CSV", action="store_true", default=False
    )
    parser.add_argument(
        "--pdf", help="Export to PDF", action="store_true", default=False
    )
    parser.add_argument("--db", help="Database file", default=DB_FILE)
    return parser.parse_args()


def process_file(args, processing_dict):
    from db import DatabaseManager

    process_id = os.getpid()
    firewall_name, file_path, date_to_use, rxp, plugins, db = args
    normalized_file_path = normalize_path(file_path)
    print(
        f"[{process_id}]  Processing file: {normalized_file_path} with date: {date_to_use} for firewall: {firewall_name}"
    )

    db = DatabaseManager(db_name=db)
    with open(file_path, "r") as f:
        output = f.read()

    device_type = detect_device_type(output, plugins)
    # Check if the file has already been processed
    if db.is_file_processed(firewall_name, device_type, normalized_file_path):
        print(
            f"[{process_id}] File {normalized_file_path} has already been processed. Skipping."
        )
        return None

    output = "\n".join(
        [line for line in output.split("\n") if not any(rx.match(line) for rx in rxp)]
    )

    key = (firewall_name, device_type)
    while key in processing_dict:
        print(
            f"[{process_id}] Waiting for {firewall_name} ({device_type}) to be available..."
        )
        time.sleep(1)

    processing_dict[key] = True

    try:
        if device_type in plugins:
            plugin = plugins[device_type]
            db.add_firewall(firewall_name, device_type)
            policies = plugin.pre_process_output(output)
            policies = plugin.process_output(policies)

            # Mark the file as processed only if processing was successful
            db.add_processed_file(
                firewall_name, device_type, normalized_file_path, date_to_use
            )

            return (firewall_name, device_type, policies, date_to_use)
        else:
            print(f"Unsupported device type for {firewall_name}")
            return None
    finally:
        del processing_dict[key]


def detect_device_type(output, plugins):
    for plugin_name, plugin in plugins.items():
        if plugin.detect_device(output):
            return plugin_name
    return "unknown"


def main():
    args = param_parser()
    os.environ["DB_FILE_HT"] = f"sqlite:///{args.db}"
    os.environ["DB_FILE"] = args.db
    data_folder = parse_folder(args)
    rxp = compile_regex_file(args)
    tracker = FirewallPolicyTracker(rxp)

    folders = order_folders_by_oldest(
        [
            os.path.join(data_folder, f)
            for f in os.listdir(data_folder)
            if os.path.isdir(os.path.join(data_folder, f))
        ]
    )

    manager = Manager()
    processing_dict = manager.dict()

    pool = multiprocessing.Pool(processes=6)

    total_updates = 0
    total_folders = len(folders)
    total_firewalls = set()

    for folder_index, folder in enumerate(folders, 1):
        folder_date = get_date_from_folder(folder)
        if folder_date:
            date_to_use = folder_date
            print(f"Processing folder: {folder} with date: {date_to_use}")
        else:
            print(
                f"Warning: Folder '{folder}' is not in the expected date format (MMDDYYYY). Using file creation dates."
            )

        if os.path.exists(folder):
            file_args = []
            for filename in os.listdir(folder):
                firewall_name = os.path.splitext(filename)[0]
                file_path = os.path.join(folder, filename)

                if not folder_date:
                    date_to_use = get_file_creation_date(file_path, folder_date)
                    print(
                        f"  Processing file: {filename} with creation date: {date_to_use}"
                    )

                file_args.append(
                    (
                        firewall_name,
                        file_path,
                        date_to_use,
                        rxp,
                        tracker.plugins,
                        args.db,
                    )
                )

            results = pool.starmap(
                process_file, [(args, processing_dict) for args in file_args]
            )

            folder_updates = []
            folder_firewalls = set()
            for result in results:
                if result:
                    firewall_name, device_type, policies, date_to_use = result
                    folder_updates.extend(
                        [
                            (
                                firewall_name,
                                device_type,
                                policy_name,
                                hit_count,
                                date_to_use,
                            )
                            for policy_name, hit_count in policies
                        ]
                    )
                    folder_firewalls.add(firewall_name)
                    total_firewalls.add(firewall_name)

            # Perform batch update for the current folder
            if folder_updates:
                tracker.db.batch_update_policies(folder_updates)
                num_updates = len(folder_updates)
                total_updates += num_updates
                print(f"Batch update completed for folder: {folder}")
                print(f"Number of updates in this folder: {num_updates}")
                print(f"Number of firewalls in this folder: {len(folder_firewalls)}")
                print(f"Total updates so far: {total_updates}")
                print(f"Total unique firewalls so far: {len(total_firewalls)}")
                print(f"Progress: {folder_index}/{total_folders} folders processed")
                print(f"Average updates per folder: {total_updates / folder_index:.2f}")
                print(
                    f"Average firewalls per folder: {len(total_firewalls) / folder_index:.2f}"
                )
                print("-" * 50)

    pool.close()
    pool.join()

    print("\nFinal Statistics:")
    print(f"Total number of updates: {total_updates}")
    print(f"Total number of folders processed: {total_folders}")
    print(f"Total number of unique firewalls: {len(total_firewalls)}")
    print(f"Average updates per folder: {total_updates / total_folders:.2f}")
    print(f"Average firewalls per folder: {len(total_firewalls) / total_folders:.2f}")

    if args.csv or args.pdf:
        report = tracker.generate_report(days_threshold=args.days)
    if args.csv:
        export_to_csv(report)
    if args.pdf:
        generate_pdf_report(report)

    tracker.db.close()


if __name__ == "__main__":
    main()
