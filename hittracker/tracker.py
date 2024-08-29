# main.py
import os
from datetime import datetime
import importlib
import pkgutil
import re
import argparse
from reports import export_to_csv, generate_pdf_report
import multiprocessing

class FirewallPolicyTracker:
    def __init__(self, rxp):
        from db import DatabaseManager
        self.db = DatabaseManager()
        self.plugins = {}
        self.load_plugins()
        self.rxp = rxp

    def load_plugins(self):
        import plugins

        for _, plugin_name, _ in pkgutil.iter_modules(plugins.__path__):
            plugin = importlib.import_module(f"plugins.{plugin_name}")
            plugin_class = getattr(plugin, f"{plugin_name.capitalize()}Plugin")
            self.plugins[plugin_name] = plugin_class()

    def process_firewall_output(self, firewall_name, output, date_to_use):
        device_type = self.detect_device_type(output)
        output = "\n".join(
            [
                line
                for line in output.split("\n")
                if not any(rx.match(line) for rx in self.rxp)
            ]
        )
        with self.db.session_scope() as session:
            if self.db.skip_import(firewall_name, device_type, date_to_use):
                return
            if device_type in self.plugins:
                plugin = self.plugins[device_type]
                self.db.add_firewall(firewall_name, device_type)
                policies = plugin.pre_process_output(output)
                policies = plugin.process_output(policies)
                for policy_name, hit_count in policies:
                    self.db.update_policy(
                        firewall_name, device_type, policy_name, hit_count, date_to_use
                    )
            else:
                print(f"Unsupported device type for {firewall_name}")

    def detect_device_type(self, output):
        for plugin_name, plugin in self.plugins.items():
            if plugin.detect_device(output):
                return plugin_name
        return "unknown"

    def generate_report(self, days_threshold):
        unused_policies = self.db.get_unused_policies(days_threshold)
        report = []
        for (
            firewall_name,
            policy_name,
            last_zero_hit,
            first_zero_hit,
        ) in unused_policies:
            if type(last_zero_hit) is not str:
                last_zero_hit = str(last_zero_hit)
            if type(first_zero_hit) is not str:
                first_zero_hit = str(first_zero_hit)
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
                    "Status": "Flagged for Removal",
                }
            )
        return report

def order_folders_by_oldest(folders):
    return sorted(folders, key=lambda x: get_date_from_folder(x) or datetime.min)

def get_date_from_folder(folder_name):
    name = os.path.basename(folder_name)
    if re.match(r"\d{8}", name):
        try:
            return datetime.strptime(name, "%m%d%Y").date()
        except ValueError:
            return None

def get_file_creation_date(file_path, folder_date=None):
    if folder_date:
        return folder_date
    return datetime.fromtimestamp(os.path.getctime(file_path)).date()

def parse_folder(args):
    folder = args.folder
    if not os.path.exists(folder):
        raise FileNotFoundError(f"Folder '{folder}' does not exist.")
    return folder

def compile_regex_file(args):
    rxp_file = args.rxp
    rx_lst = [re.compile("^#.*")]
    if os.path.exists(rxp_file):
        with open(rxp_file, "r") as f:
            lines = f.readlines()
        for line in lines:
            try:
                rx_lst.append(re.compile(line.strip()))
            except re.error:
                print(f"Error compiling regex: {line.strip()}")
    else:
        print(f"Error: Regex file '{rxp_file}' does not exist...skipping..using default regex")
    return rx_lst

def param_parser():
    parser = argparse.ArgumentParser(description="Firewall Policy Tracker")
    parser.add_argument("-f", "--folder", help="Folder to process", required=True)
    parser.add_argument("-d", "--days", help="Days threshold for removal", type=int, default=90)
    parser.add_argument(
        "-r",
        "--rxp",
        help="Regex file for filtering, file stored in current folder or path to file",
        default="filter.rxp",
        required=False,
        dest="rxp",
    )
    parser.add_argument("--csv", help="Export to CSV", action="store_true", default=False)
    parser.add_argument("--pdf", help="Export to PDF", action="store_true", default=False)
    return parser.parse_args()

def process_file(args):
    from db import DatabaseManager
    firewall_name, file_path, date_to_use, rxp, plugins = args
    db = DatabaseManager()
    
    with open(file_path, "r") as f:
        output = f.read()
    
    device_type = detect_device_type(output, plugins)
    output = "\n".join(
        [
            line
            for line in output.split("\n")
            if not any(rx.match(line) for rx in rxp)
        ]
    )
    
    with db.session_scope() as session:
        if db.skip_import(firewall_name, device_type, date_to_use):
            return
        if device_type in plugins:
            plugin = plugins[device_type]
            db.add_firewall(firewall_name, device_type)
            policies = plugin.pre_process_output(output)
            policies = plugin.process_output(policies)
            for policy_name, hit_count in policies:
                db.update_policy(
                    firewall_name, device_type, policy_name, hit_count, date_to_use
                )
        else:
            print(f"Unsupported device type for {firewall_name}")

def detect_device_type(output, plugins):
    for plugin_name, plugin in plugins.items():
        if plugin.detect_device(output):
            return plugin_name
    return "unknown"

def main():
    args = param_parser()
    folder = parse_folder(args)
    rxp = compile_regex_file(args)

    tracker = FirewallPolicyTracker(rxp)

    folders = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isdir(os.path.join(folder, f))]
    folders = order_folders_by_oldest(folders)
    
    pool = multiprocessing.Pool()
    
    for folder in folders:
        folder_date = get_date_from_folder(folder)
        if folder_date:
            date_to_use = folder_date
            print(f"Processing folder: {folder} with date: {date_to_use}")
        else:
            print(f"Warning: Folder '{folder}' is not in the expected date format (MMDDYYYY). Using file creation dates.")

        if os.path.exists(folder):
            file_args = []
            for filename in os.listdir(folder):
                firewall_name = os.path.splitext(filename)[0]
                file_path = os.path.join(folder, filename)

                if not folder_date:
                    date_to_use = get_file_creation_date(file_path, folder_date)
                    print(f"  Processing file: {filename} with creation date: {date_to_use}")

                file_args.append((firewall_name, file_path, date_to_use, rxp, tracker.plugins))

            pool.map(process_file, file_args)

    pool.close()
    pool.join()

    if args.csv or args.pdf:
        report = tracker.generate_report(days_threshold=args.days)
    if args.csv:
        export_to_csv(report)
    if args.pdf:
        generate_pdf_report(report)

    tracker.db.close()

if __name__ == "__main__":
    main()
