-- CTI_PLATFORM_DATABASE: use PUBLIC for all CTI core tables.
-- Drops CURATED / AGENT / MONITOR if they exist (CASCADE removes objects inside).
-- Prerequisite: role must OWN or have rights to drop those schemas if present.

USE DATABASE CTI_PLATFORM_DATABASE;

DROP SCHEMA IF EXISTS CURATED CASCADE;
DROP SCHEMA IF EXISTS AGENT CASCADE;
DROP SCHEMA IF EXISTS MONITOR CASCADE;

USE SCHEMA PUBLIC;
