-- ==============================================================================
-- Filename: investigation_queries.sql
-- Description: SQL queries used during an incident response investigation to
--              track down rogue database access and unauthorized after-hours logins.
-- ==============================================================================

-- 🎯 SCENARIO 1: INVESTIGATING FAILED LOGINS AFTER HOURS
-- Objective: Identify potential brute-force or unauthorized access attempts that 
-- occurred after standard business hours (18:00) from external IP addresses.

SELECT login_id, username, login_time, ip_address, login_status
FROM user_login_logs
WHERE login_status = 'FAILED'
  AND TIME(login_time) >= '18:00:00'
ORDER BY login_time DESC;


-- 🎯 SCENARIO 2: TRACING AN INSIDER THREAT (RECONNAISSANCE DETECTED)
-- Objective: Locate all activity from employee 'jdoe' who is suspected of looking 
-- at sensitive financial tables they do not have authorization to view.

SELECT timestamp, employee_id, username, action_performed, resource_table, ip_address
FROM data_access_audit
WHERE username = 'jdoe'
  AND (resource_table LIKE '%financial%' OR resource_table LIKE '%salary%')
ORDER BY timestamp DESC;


-- 🎯 SCENARIO 3: TRACKING MULTIPLE IPS PER USER ACCOUNT
-- Objective: Audit accounts that have authenticated from more than one distinct Class C 
-- subnet within a 24-hour window, indicating potential session hijacking or credential sharing.

SELECT username, COUNT(DISTINCT ip_address) AS unique_ips_used
FROM user_login_logs
WHERE login_status = 'SUCCESS'
GROUP BY username
HAVING COUNT(DISTINCT ip_address) > 1
ORDER BY unique_ips_used DESC;