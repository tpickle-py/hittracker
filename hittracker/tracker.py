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
    get_rule_details,
    pack_rule_details,
    unpack_rule_details,
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
            rule_details,
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
            report_entry = {
                "Firewall": firewall_name,
                "Policy": policy_name,
                "Last Seen Unused": last_zero_hit,
                "First Seen Unused": first_zero_hit,
                "Days Since Last Import": days_since_last_import,
                "Total Days Unused": total_days_unused,
                "Captures": captures,
                "Status": "Flagged for Removal",
                "rule_details": rule_details,
            }
            report.append(report_entry)
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


def process_file_chunk(file_chunk, rxp, plugins, db):
    from db import DatabaseManager

    process_id = os.getpid()
    db = DatabaseManager(db_name=db)

    results = []
    for firewall_name, file_path, date_to_use in file_chunk:
        normalized_file_path = normalize_path(file_path)
        print(
            f"[{process_id}]  Processing file: {normalized_file_path} with date: {date_to_use} for firewall: {firewall_name}"
        )

        with open(file_path, "r") as f:
            output = f.read()

        device_type = detect_device_type(output, plugins)
        
        # Check if the file has been processed and if rule details are complete
        file_processed = db.is_file_processed(firewall_name, device_type, normalized_file_path)
        rule_details_complete = db.are_rule_details_complete(firewall_name, device_type)

        if file_processed and rule_details_complete:
            print(
                f"[{process_id}] File {normalized_file_path} has already been processed and rule details are complete. Skipping."
            )
            continue

        output = "\n".join(
            [
                line
                for line in output.split("\n")
                if not any(rx.match(line) for rx in rxp)
            ]
        )

        if device_type in plugins:
            plugin = plugins[device_type]
            db.add_firewall(firewall_name, device_type)
            policies = plugin.pre_process_output(output)
            policies = plugin.process_output(policies)

            # Get the latest config file for the firewall
            config_file = db.get_latest_config(firewall_name, device_type)
            if not config_file:
                print(f"[{process_id}] Warning: No config file found for {firewall_name}")
                continue

            with open(config_file, "r") as f:
                config = f.read()

            # Process all policies for the firewall
            policies_with_details = []
            for policy_name, hit_count in policies:
                rule_details = get_rule_details(plugin, policy_name, config)
                
                # Check if rule details are incomplete
                if any(len(value) == 0 for key, value in rule_details.items() if key not in ['Source Services', 'Destination Services']):
                    print(f"[{process_id}] Warning: Incomplete rule details for policy {policy_name} on {firewall_name}.")
                    print(f"[{process_id}] Rule details: {rule_details}")
                    print(f"[{process_id}] Attempting to reprocess rule details...")
                    
                    # Attempt to reprocess the rule details
                    rule_details = get_rule_details(plugin, policy_name, config)
                    
                    if any(len(value) == 0 for key, value in rule_details.items() if key not in ['Source Services', 'Destination Services']):
                        print(f"[{process_id}] Warning: Still incomplete rule details for policy {policy_name} on {firewall_name} after reprocessing.")
                        print(f"[{process_id}] Final rule details: {rule_details}")
                    else:
                        print(f"[{process_id}] Successfully reprocessed rule details for policy {policy_name} on {firewall_name}.")

                packed_rule_details = pack_rule_details(rule_details)
                policies_with_details.append(
                    (policy_name, hit_count, packed_rule_details)
                )
                db.update_policy_details(firewall_name, device_type, policy_name, rule_details)

            # Mark the file as processed only if processing was successful
            db.add_processed_file(
                firewall_name, device_type, normalized_file_path, date_to_use
            )

            results.append(
                (firewall_name, device_type, policies_with_details, date_to_use)
            )
        else:
            print(f"[{process_id}] Unsupported device type for {firewall_name}")

    return results


def detect_device_type(output, plugins):
    for plugin_name, plugin in plugins.items():
        if plugin.detect_device(output):
            return plugin_name
    return "unknown"


def chunk_files(file_list, num_chunks):
    chunk_size = max(1, len(file_list) // num_chunks)
    return [file_list[i : i + chunk_size] for i in range(0, len(file_list), chunk_size)]


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

    # Dynamically determine the number of processes
    num_processes = max(1, multiprocessing.cpu_count() - 1)
    print(f"Using {num_processes} processes for multiprocessing")

    pool = multiprocessing.Pool(processes=num_processes)

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

                file_args.append((firewall_name, file_path, date_to_use))

            # Chunk the files
            file_chunks = chunk_files(file_args, num_processes)

            # Process chunks in parallel
            chunk_results = pool.starmap(
                process_file_chunk,
                [(chunk, rxp, tracker.plugins, args.db) for chunk in file_chunks],
            )

            # Flatten the results
            results = [item for sublist in chunk_results for item in sublist]

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
                                rule_details,
                            )
                            for policy_name, hit_count, rule_details in policies
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
