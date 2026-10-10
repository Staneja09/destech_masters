-- ============================================
-- DesTech Masters: Database Schema
-- File: database/schema.sql
-- ============================================

CREATE DATABASE IF NOT EXISTS des_tech_masters
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE des_tech_masters;

-- ============================================
-- 1. USERS
-- ============================================

CREATE TABLE IF NOT EXISTS users (
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
full_name VARCHAR(100) NOT NULL,
email VARCHAR(254) NOT NULL UNIQUE,
password_hash VARCHAR(255) NOT NULL,
role ENUM('admin', 'member') NOT NULL DEFAULT 'member',
created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================
-- 2. HACKATHONS
-- ============================================

CREATE TABLE IF NOT EXISTS hackathons (
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
title VARCHAR(200) NOT NULL,
description TEXT,
organizer VARCHAR(200),
venue VARCHAR(255),
event_url VARCHAR(1000),
start_date DATETIME NOT NULL,
end_date DATETIME NOT NULL,
registration_deadline DATETIME,
status ENUM(
'upcoming',
'open',
'ongoing',
'completed',
'cancelled'
) NOT NULL DEFAULT 'upcoming',
created_by INT UNSIGNED,
created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
ON UPDATE CURRENT_TIMESTAMP,

```
CONSTRAINT fk_hackathons_created_by
    FOREIGN KEY (created_by) REFERENCES users(id)
    ON DELETE SET NULL,

INDEX idx_hackathons_start_date (start_date),
INDEX idx_hackathons_status (status)
```

) ENGINE=InnoDB;

-- ============================================
-- 3. MEMBER AVAILABILITY
-- Members can indicate whether they are available
-- for a particular hackathon.
-- ============================================

CREATE TABLE IF NOT EXISTS hackathon_availability (
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
hackathon_id INT UNSIGNED NOT NULL,
user_id INT UNSIGNED NOT NULL,
is_available BOOLEAN NOT NULL DEFAULT TRUE,
notes VARCHAR(500),
updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
ON UPDATE CURRENT_TIMESTAMP,

```
CONSTRAINT uq_availability_hackathon_user
    UNIQUE (hackathon_id, user_id),

CONSTRAINT fk_availability_hackathon
    FOREIGN KEY (hackathon_id) REFERENCES hackathons(id)
    ON DELETE CASCADE,

CONSTRAINT fk_availability_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE
```

) ENGINE=InnoDB;

-- ============================================
-- 4. TEAM LINEUPS
-- A lineup represents the selected team for an event.
-- ============================================

CREATE TABLE IF NOT EXISTS team_lineups (
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
hackathon_id INT UNSIGNED NOT NULL,
lineup_name VARCHAR(150) NOT NULL DEFAULT 'Main Team',
created_by INT UNSIGNED,
created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

```
CONSTRAINT uq_lineup_event_name
    UNIQUE (hackathon_id, lineup_name),

CONSTRAINT fk_lineups_hackathon
    FOREIGN KEY (hackathon_id) REFERENCES hackathons(id)
    ON DELETE CASCADE,

CONSTRAINT fk_lineups_created_by
    FOREIGN KEY (created_by) REFERENCES users(id)
    ON DELETE SET NULL
```

) ENGINE=InnoDB;

-- ============================================
-- 5. LINEUP MEMBERS
-- ============================================

CREATE TABLE IF NOT EXISTS lineup_members (
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
lineup_id INT UNSIGNED NOT NULL,
user_id INT UNSIGNED NOT NULL,
team_position VARCHAR(100),
added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

```
CONSTRAINT uq_lineup_member
    UNIQUE (lineup_id, user_id),

CONSTRAINT fk_lineup_members_lineup
    FOREIGN KEY (lineup_id) REFERENCES team_lineups(id)
    ON DELETE CASCADE,

CONSTRAINT fk_lineup_members_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE
```

) ENGINE=InnoDB;

-- ============================================
-- 6. HACKATHON RESULTS
-- ============================================

CREATE TABLE IF NOT EXISTS hackathon_results (
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
hackathon_id INT UNSIGNED NOT NULL,
team_name VARCHAR(150),
placement INT UNSIGNED,
score DECIMAL(12, 2),
outcome ENUM('win', 'participated', 'withdrawn', 'disqualified')
NOT NULL DEFAULT 'participated',
notes TEXT,
recorded_by INT UNSIGNED,
recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

```
CONSTRAINT fk_results_hackathon
    FOREIGN KEY (hackathon_id) REFERENCES hackathons(id)
    ON DELETE CASCADE,

CONSTRAINT fk_results_recorded_by
    FOREIGN KEY (recorded_by) REFERENCES users(id)
    ON DELETE SET NULL,

INDEX idx_results_hackathon (hackathon_id),
INDEX idx_results_outcome (outcome)
```

) ENGINE=InnoDB;

-- ============================================
-- 7. RESULT PARTICIPANTS
-- Tracks which members participated in each result.
-- ============================================

CREATE TABLE IF NOT EXISTS result_participants (
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
result_id INT UNSIGNED NOT NULL,
user_id INT UNSIGNED NOT NULL,

```
CONSTRAINT uq_result_participant
    UNIQUE (result_id, user_id),

CONSTRAINT fk_participants_result
    FOREIGN KEY (result_id) REFERENCES hackathon_results(id)
    ON DELETE CASCADE,

CONSTRAINT fk_participants_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE
```

) ENGINE=InnoDB;

-- ============================================
-- 8. COMPETITIVE PROGRAMMING PROFILES
-- Stores usernames and profile URLs, not passwords.
-- ============================================

CREATE TABLE IF NOT EXISTS coding_profiles (
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
user_id INT UNSIGNED NOT NULL,
platform ENUM(
'Codeforces',
'LeetCode',
'CodeChef',
'HackerRank',
'AtCoder',
'Other'
) NOT NULL,
username VARCHAR(150) NOT NULL,
profile_url VARCHAR(1000),
rating INT,
problems_solved INT UNSIGNED DEFAULT 0,
updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
ON UPDATE CURRENT_TIMESTAMP,

```
CONSTRAINT uq_user_platform
    UNIQUE (user_id, platform),

CONSTRAINT fk_coding_profiles_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE
```

) ENGINE=InnoDB;

-- ============================================
-- 9. COMPETITIVE PROGRAMMING HISTORY
-- Optional snapshots of ratings and solved counts.
-- ============================================

CREATE TABLE IF NOT EXISTS coding_history (
id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
profile_id INT UNSIGNED NOT NULL,
rating INT,
problems_solved INT UNSIGNED DEFAULT 0,
recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

```
CONSTRAINT fk_coding_history_profile
    FOREIGN KEY (profile_id) REFERENCES coding_profiles(id)
    ON DELETE CASCADE,

INDEX idx_coding_history_profile_date
    (profile_id, recorded_at)
```

) ENGINE=InnoDB;

-- ============================================
-- END OF SCHEMA
-- ============================================
