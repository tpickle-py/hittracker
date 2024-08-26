# main.py
import os
from datetime import datetime
import importlib
import pkgutil
from db_manager import DatabaseManager
import re
import argparse


class FirewallPolicyTracker:
    def __init__(
        self,
        rxp,
    ):
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

    def process_firewall_output(self, firewall_name, output, date):
        device_type = self.detect_device_type(output)
        output = "\n".join(
            [
                line
                for line in output.split("\n")
                if not any(rx.match(line) for rx in self.rxp)
            ]
        )
        if device_type in self.plugins:
            plugin = self.plugins[device_type]
            self.db.add_firewall(firewall_name, device_type)
            policies = plugin.pre_process_output(output)
            policies = plugin.process_output(policies)
            for policy_name, hit_count in policies:
                self.db.update_policy(firewall_name, policy_name, hit_count, date)
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
    # sort folders by date
    # text format is MMDDYYYY
    # should be converted to date format
    # converted back to text format after sorting
    for folder in folders:
        folder_date = get_date_from_folder(folder)
        if not folder_date:
            raise ValueError(
                f"Warning: Folder '{folder}' is not in the expected date format (MMDDYYYY). Using file creation dates."
            )

    return sorted(folders, key=lambda x: get_date_from_folder(x))


def get_date_from_folder(folder_name):
    print(folder_name)
    # keep only the current folder name, do not keep the full path
    name = os.path.basename(folder_name)
    if re.match("\d{8}", name):
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


def make_firewall_tracker(args): ...


def compile_regex_file(args):
    rxp_file = args.rxp
    rx_lst = [
        (re.compile("^#.*")),
    ]
    if os.path.exists(rxp_file):
        with open(rxp_file, "r") as f:
            lines = f.readlines()
        for line in lines:
            try:
                rx_lst.append(re.compile(line.strip()))
            except re.error:
                print(f"Error compiling regex: {line.strip()}")
    else:
        print(
            f"Error: Regex file '{rxp_file}' does not exist...skipping..using default regex"
        )
    return rx_lst


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
    return parser.parse_args()


def main():
    args = param_parser()
    folder = parse_folder(args)
    rxp = compile_regex_file(args)

    tracker = FirewallPolicyTracker(rxp)

    folders = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if os.path.isdir(os.path.join(folder, f))
    ]
    folders = order_folders_by_oldest(folders)
    for folder in folders:
        folder_date = get_date_from_folder(folder)
        if folder_date:
            date_to_use = folder_date
            print(f"Processing folder: {folder} with date: {date_to_use}")
        else:
            print(
                f"Warning: Folder '{folder}' is not in the expected date format (MMDDYYYY). Using file creation dates."
            )

        if os.path.exists(folder):
            for filename in os.listdir(folder):
                firewall_name = os.path.splitext(filename)[0]
                file_path = os.path.join(folder, filename)

                if not folder_date:
                    date_to_use = get_file_creation_date(file_path, folder_date)
                    print(
                        f"  Processing file: {filename} with creation date: {date_to_use}"
                    )

                with open(file_path, "r") as f:
                    output = f.read()

                tracker.process_firewall_output(firewall_name, output, date_to_use)

    report = tracker.generate_report(days_threshold=args.days)

    if report:
        print("\nPolicies flagged for removal:")
        for policy in report:
            print(f"Firewall: {policy['Firewall']}, Policy: {policy['Policy']}")
            print(f"  Last Seen Unused: {policy['Last Seen Unused']}")
            print(f"  First Seen Unused: {policy['First Seen Unused']}")
            print(f"  Days Since Last Import: {policy['Days Since Last Import']}")
            print(f"  Total Days Unused: {policy['Total Days Unused']}")
            print()
    else:
        print("\nNo policies flagged for removal at this time.")

    tracker.db.close()


if __name__ == "__main__":
    main()
