"""
Filename: allow_list_updater.py
Description: Automatically updates a network access control 'allow list' by 
             removing specified malicious or revoked IP addresses.
"""

def update_allow_list(import_file, remove_list):
    # 1. Open the file and read the current allowed IPs
    with open(import_file, "r") as file:
        current_allow_list = file.read()

    # 2. Convert the string of IPs into a clean Python list
    ip_list = current_allow_list.split()

    # 3. Iterate through the removal list and strip out banned IPs
    for ip in remove_list:
        if ip in ip_list:
            ip_list.remove(ip)
            print(f"[REMOVED] Revoked IP {ip} has been removed from the allow list.")
        else:
            print(f"[INFO] IP {ip} was not found in the active allow list.")

    # 4. Re-format the list back into a single string with newlines
    updated_allow_list = "\n".join(ip_list)

    # 5. Overwrite the original file with the newly secured list
    with open(import_file, "w") as file:
        file.write(updated_allow_list)
        
    print("\n[SUCCESS] The allow list file has been successfully updated.")

# --- Execution Block ---
if __name__ == "__main__":
    # Define the target file and the IPs flagged for removal
    target_file = "allow_list.txt"
    banned_ips = ["192.168.1.50", "10.0.0.22", "8.8.8.8"]  # Note: 8.8.8.8 is a test case not in the list

    print(f"Starting security sweep on {target_file}...\n")
    update_allow_list(target_file, banned_ips)