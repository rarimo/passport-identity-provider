package cli

import (
	"github.com/rarimo/passport-identity-provider/internal/assets"
	"github.com/rarimo/passport-identity-provider/internal/config"

	migrate "github.com/rubenv/sql-migrate"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

var migrations = &migrate.EmbedFileSystemMigrationSource{
	FileSystem: assets.Migrations,
	Root:       "migrations",
}

func MigrateUp(cfg config.Config) error {
	applied, err := migrate.Exec(cfg.DB().RawDB(), "postgres", migrations, migrate.Up)
	if err != nil {
		return errors.Wrap(err, "failed to apply migrations")
	}
	cfg.Log().WithField("applied", applied).Info("migrations applied")
	return nil
}

func MigrateDown(cfg config.Config) error {
	applied, err := migrate.Exec(cfg.DB().RawDB(), "postgres", migrations, migrate.Down)
	if err != nil {
		return errors.Wrap(err, "failed to apply migrations")
	}
	cfg.Log().WithField("applied", applied).Info("migrations applied")
	return nil
}
