# Allow-list filtering demo

This script removes revoked entries into a separate output file, leaving the source allow-list unchanged. It preserves the order of remaining entries and removes every occurrence of a revoked value.

Run from the repository root with Python:

    python "google-cybersecurity/python-automation/Automated Log File Access/allow_list_updater.py" "google-cybersecurity/python-automation/Automated Log File Access/allow_list.txt" filtered_allow_list.txt --remove 192.168.1.50 10.0.0.22

The included list is sample data. Review the filtered output before using it in any access-control system.
