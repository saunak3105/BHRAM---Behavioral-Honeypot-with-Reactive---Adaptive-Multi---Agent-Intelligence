-- BHRAM Technologies Database Backup
-- Generated: 2025-09-01 02:00:01 UTC
-- Database: bhram_prod_db @ db-primary.bhram-technologies.internal
-- Version: PostgreSQL 15.4
-- CONFIDENTIAL — Internal use only
-- ========================================================================

-- This file is a FICTIONAL decoy. All data below is fake/bait content.
-- Real credentials, real IPs, and real data are NOT present.

-- pg_dump output (excerpt)
\connect bhram_prod_db

SET statement_timeout = 0;
SET client_encoding = 'UTF8';

-- Users table (excerpt)
COPY users (id, username, email, password_hash, role, created_at) FROM stdin;
1	admin	a.mercer@bhram-technologies.internal	$2b$12$FAKEHASH_NOT_REAL_IXJFWfk7ZzLqR9v	admin	2023-01-15 09:12:00
2	developer	s.nakamura@bhram-technologies.internal	$2b$12$FAKEHASH_NOT_REAL_aQdGhKmNpRwUxYz	engineer	2023-01-15 09:15:00
3	finance	m.chen@bhram-technologies.internal	$2b$12$FAKEHASH_NOT_REAL_bSeTgJlOqVxAcFi	finance	2023-02-01 10:00:00
\.

-- API keys (FAKE — deception artifact)
-- Production API key (retired): bhram_live_FAKE_KEY_NOT_REAL_7x2mK9pNqRvTwY
-- Staging API key: bhram_test_FAKE_KEY_NOT_REAL_3aZdJeLnOsUcXfH

-- Internal service endpoints:
--   Primary DB:  postgresql://bhram_user:FAKE_PASS@db-primary.internal:5432/bhram_prod_db
--   Replica:     postgresql://bhram_ro:FAKE_PASS@db-replica.internal:5432/bhram_prod_db
--   Redis:       redis://:FAKE_PASS@redis.internal:6379/0
--   Elasticsearch: http://es-cluster.internal:9200
