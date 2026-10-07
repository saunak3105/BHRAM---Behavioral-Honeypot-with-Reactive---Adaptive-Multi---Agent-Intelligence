-- =============================================================================
-- BHRAM Seed Data — Fictional Data Only
-- ALL names, emails, IPs, and credentials are entirely fictional.
-- DO NOT use real personal data in this file.
-- =============================================================================

-- ── Fake company users (SSH honeypot + web portal users) ─────────────────────
INSERT INTO users (username, full_name, email, department, role, is_decoy, ssh_enabled, home_dir) VALUES
('admin',        'Alex Mercer',      'a.mercer@bhram-technologies.internal',      'IT',          'admin',     TRUE, TRUE,  '/home/admin'),
('it_support',   'Jordan Ellis',     'j.ellis@bhram-technologies.internal',       'IT Support',  'it_support',TRUE, TRUE,  '/home/it_support'),
('developer',    'Sam Nakamura',     's.nakamura@bhram-technologies.internal',    'Engineering', 'developer', TRUE, TRUE,  '/home/developer'),
('finance',      'Morgan Chen',      'm.chen@bhram-technologies.internal',        'Finance',     'finance',   TRUE, TRUE,  '/home/finance'),
('hr_manager',   'Riley Patel',      'r.patel@bhram-technologies.internal',       'HR',          'hr',        TRUE, TRUE,  '/home/hr_manager'),
('intern',       'Casey Thompson',   'c.thompson@bhram-technologies.internal',    'Engineering', 'intern',    TRUE, TRUE,  '/home/intern')
ON CONFLICT (username) DO NOTHING;

-- ── Initial services registry ─────────────────────────────────────────────────
INSERT INTO services (name, description, status, host, port, protocol, is_honeypot, is_decoy, network, docker_name) VALUES
('bhram-web',       'BHRAM Technologies Website',    'running',  'web',         5000,  'http',  FALSE, TRUE,  'frontend', 'bhram_web'),
('bhram-api',       'BHRAM Internal REST API',       'running',  'bhram-api',   8000,  'http',  FALSE, FALSE, 'backend',  'bhram_api'),
('bhram-fileserver','BHRAM Deception File Server',   'running',  'fileserver',  8081,  'http',  FALSE, TRUE,  'backend',  'bhram_fileserver'),
('cowrie-ssh',      'Cowrie SSH Honeypot',           'honeypot', 'cowrie',      2222,  'ssh',   TRUE,  TRUE,  'frontend', 'bhram_cowrie'),
('postgres',        'PostgreSQL Database',           'running',  'postgres',    5432,  'tcp',   FALSE, FALSE, 'internal', 'bhram_postgres')
ON CONFLICT (name) DO NOTHING;

-- ── Decoy files ───────────────────────────────────────────────────────────────
INSERT INTO decoy_files (filename, filepath, content_type, size_bytes, bait_level) VALUES
('vpn_config.txt',            '/home/admin/vpn_config.txt',                        'text/plain',  1024,  4),
('employee_directory.csv',    '/srv/internal/employee_directory.csv',               'text/csv',    8192,  3),
('salary_structure.csv',      '/home/finance/salary_structure.csv',                 'text/csv',    4096,  5),
('database_backup.sql',       '/home/admin/backup/database_backup.sql',             'text/plain',  65536, 5),
('developer_notes.txt',       '/home/developer/developer_notes.txt',                'text/plain',  2048,  3),
('network_inventory.txt',     '/home/it_support/network_inventory.txt',             'text/plain',  3072,  4),
('it_support_notes.txt',      '/home/it_support/it_support_notes.txt',              'text/plain',  1536,  3),
('api_keys_archive.txt',      '/home/developer/archive/api_keys_archive.txt',       'text/plain',  512,   5),
('hr_performance_q4.xlsx',    '/home/hr_manager/hr_performance_q4.xlsx',            'application/vnd.ms-excel', 16384, 4),
('internal_roadmap_2026.pdf', '/srv/internal/docs/internal_roadmap_2026.pdf',       'application/pdf', 204800, 3)
ON CONFLICT DO NOTHING;

-- ── Initial environment state ─────────────────────────────────────────────────
INSERT INTO environment_state (deception_mode, is_current, state, notes) VALUES (
    'baseline',
    TRUE,
    '{
        "company": "BHRAM Technologies",
        "deception_mode": "baseline",
        "services": [
            {"name": "bhram-web",        "status": "running"},
            {"name": "cowrie-ssh",       "status": "honeypot"},
            {"name": "bhram-fileserver", "status": "running"},
            {"name": "bhram-api",        "status": "running"}
        ],
        "users": ["admin","it_support","developer","finance","hr_manager","intern"],
        "active_decoys": 10,
        "network": {
            "frontend_subnet": "172.20.0.0/24",
            "backend_subnet":  "172.21.0.0/24",
            "internal_subnet": "172.22.0.0/24"
        }
    }'::JSONB,
    'Initial Part 1 baseline state — no AI/ML agents active yet'
);
