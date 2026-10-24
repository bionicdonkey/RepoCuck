-- Soft-deleted variants are hard-deleted (and their blobs reclaimed) after a grace period.
alter table package_variants add column tombstoned_at timestamptz;
create index package_variants_tombstoned on package_variants (tombstoned_at) where state = 'tombstoned';
