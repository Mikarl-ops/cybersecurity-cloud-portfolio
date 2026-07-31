-- ==============================================================================
-- Filename: privilege_escalation_audit.sql
-- Description: Investigates unauthorized role modifications and detects users who
--              performed administrative actions without standard SOC approval.
-- ==============================================================================

-- 🎯 SCENARIO 1: IDENTIFYING RECENT ADMIN ROLE ASSIGNMENTS
-- Objective: Audit the role change tables to find any accounts that were granted 
-- 'SUPERADMIN' or 'DB_ADMIN' privileges within the last 7 days.

SELECT change_id, target_user, modified_by, new_role, timestamp
FROM role_modification_log
WHERE new_role IN ('SUPERADMIN', 'DB_ADMIN')
  AND timestamp >= NOW() - INTERVAL '7 DAYS'
ORDER BY timestamp DESC;


-- 🎯 SCENARIO 2: HUNTING FOR UNAUTHORIZED PERMISSION CHANGES
-- Objective: Find instances where a user modified another user's permissions, BUT 
-- the person making the change was NOT a member of the IT Security group.

SELECT r.timestamp, r.modified_by, u.department, r.target_user, r.new_role
FROM role_modification_log r
JOIN employee_directory u ON r.modified_by = u.username
WHERE u.department != 'IT Security'
ORDER BY r.timestamp DESC;


-- 🎯 SCENARIO 3: TRACKING FORMER EMPLOYEES WITH ACTIVE SESSIONS
-- Objective: Cross-reference HR termination tables against active database sessions
-- to catch orphaned accounts being used for unauthorized persistence.

SELECT s.session_id, s.username, s.login_time, h.termination_date, s.ip_address
FROM active_user_sessions s
JOIN hr_employee_status h ON s.username = h.username
WHERE h.employment_status = 'TERMINATED'
  AND s.login_time > h.termination_date;