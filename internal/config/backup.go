package config

import (
	"regexp"
	"slices"
	"time"
)

// Backup configures backups of the rows changed by approved writes.
//
// Before an approved (or break-glass) UPDATE or DELETE runs, the rows it
// will change are copied into a new table in Schema, in the same
// transaction as the write. The write user needs CREATE on Schema.
type Backup struct {
	// Schema holds the backup tables. It must already exist.
	Schema string `yaml:"schema"`
	// Required refuses UPDATE, DELETE and MERGE statements that cannot be
	// backed up (for example UPDATE ... FROM) instead of running them
	// without a backup.
	Required bool `yaml:"required"`
	// Retention drops backup tables older than this (0 keeps them).
	Retention Duration `yaml:"retention"`
}

var backupSchemaRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func (b *Backup) validate(db *Database, p string, add func(string, ...any)) {
	if db.Type != "postgres" {
		add("%s: backups are only supported for postgres databases", p)
	}
	if !backupSchemaRE.MatchString(b.Schema) {
		add("%s.schema: required; a lower-case unquoted identifier (letters, digits and _)", p)
	}
	if slices.Contains(db.SearchPath, b.Schema) {
		add("%s.schema: must not be in the database's search_path", p)
	}
	if r := b.Retention.D(); r != 0 && r < time.Hour {
		add("%s.retention: must be at least 1h (or omitted to keep backups)", p)
	}
	if db.Primary.WriteUser == "" {
		add("%s: requires primary.write_user (backups are taken by the write user)", p)
	}
}
