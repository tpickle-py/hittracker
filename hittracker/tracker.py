# main.py
import os
from datetime import datetime
import importlib
import pkgutil
from db_manager import DatabaseManager

class FirewallPolicyTracker:
    def __init__(self):
        self.db = DatabaseManager()
        self.plugins = {}
        self.load_plugins()

    def load_plugins(self):
        import plugins
        for _, plugin_name, _ in pkgutil.iter_modules(plugins.__path__):
            plugin = importlib.import_module(f'plugins.{plugin_name}')
            plugin_class = getattr(plugin, f"{plugin_name.capitalize()}Plugin")
            self.plugins[plugin_name] = plugin_class()

    def process_firewall_output(self, firewall_name, output, date):
        device_type = self.detect_device_type(output)
        if device_type in self.plugins:
            plugin = self.plugins[device_type]
            self.db.add_firewall(firewall_name, device_type)
            policies = plugin.process_output(output)
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
        for firewall_name, policy_name, last_zero_hit, first_zero_hit in unused_policies:
            days_unused = (datetime.now().date() - datetime.strptime(last_zero_hit, '%Y-%m-%d').date()).days
            total_days_unused = (datetime.now().date() - datetime.strptime(first_zero_hit, '%Y-%m-%d').date()).days
            report.append({
                'Firewall': firewall_name,
                'Policy': policy_name,
                'Last Seen Unused': last_zero_hit,
                'First Seen Unused': first_zero_hit,
                'Days Unused': days_unused,
                'Total Days Unused': total_days_unused,
                'Status': 'Flagged for Removal'
            })
        return report

def get_date_from_folder(folder_name):
    try:
        return datetime.strptime(folder_name, '%m%d%Y').date()
    except ValueError:
        return None

def get_file_creation_date(file_path):
    return datetime.fromtimestamp(os.path.getctime(file_path)).date()

def main():
    tracker = FirewallPolicyTracker()
    
    folders = [f for f in os.listdir() if os.path.isdir(f)]
    
    for folder in folders:
        folder_date = get_date_from_folder(folder)
        
        if folder_date:
            date_to_use = folder_date
            print(f"Processing folder: {folder} with date: {date_to_use}")
        else:
            print(f"Warning: Folder '{folder}' is not in the expected date format (MMDDYYYY). Using file creation dates.")
        
        if os.path.exists(folder):
            for filename in os.listdir(folder):
                firewall_name = os.path.splitext(filename)[0]
                file_path = os.path.join(folder, filename)
                
                if not folder_date:
                    date_to_use = get_file_creation_date(file_path)
                    print(f"  Processing file: {filename} with creation date: {date_to_use}")
                
                with open(file_path, 'r') as f:
                    output = f.read()
                
                tracker.process_firewall_output(firewall_name, output, date_to_use)

    report = tracker.generate_report(days_threshold=30)
    
    if report:
        print("\nPolicies flagged for removal:")
        for policy in report:
            print(f"Firewall: {policy['Firewall']}, Policy: {policy['Policy']}")
            print(f"  Last Seen Unused: {policy['Last Seen Unused']}")
            print(f"  First Seen Unused: {policy['First Seen Unused']}")
            print(f"  Days Unused: {policy['Days Unused']}")
            print(f"  Total Days Unused: {policy['Total Days Unused']}")
            print()
    else:
        print("\nNo policies flagged for removal at this time.")

    tracker.db.close()

if __name__ == "__main__":
    main()


