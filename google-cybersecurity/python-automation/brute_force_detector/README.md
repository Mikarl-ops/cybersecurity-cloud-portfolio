# Failed-login burst detector

The detector reads timestamped authentication log lines and counts failed-login events per source IP in a rolling time window. By default it reports sources with at least five failures in 300 seconds. It ignores malformed timestamps and invalid IPv4 addresses.

Run from the project directory with Python:

    python failed_login_detector.py server_auth.log

The included log is synthetic. This is a small parser demonstration; production logs may use different formats, time zones, event fields, or deduplication rules. Tune the time window and threshold to the environment.
