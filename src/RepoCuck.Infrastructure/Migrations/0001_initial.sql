-- RepoCuck initial schema (see docs/IMPLEMENTATION_SPEC.md §3.2)
create extension if not exists citext;

-- ---------------------------------------------------------------- identity
create table users (
    id                    uuid primary key,
    username              citext not null unique,
    email                 citext,
    display_name          text   not null,
    password_hash         text,                          -- null => SSO-only account
    role                  text   not null check (role in ('admin','member')),
    role_locked           boolean not null default false,
    is_active             boolean not null default true, -- accounts are disabled, never hard-deleted
    must_change_password  boolean not null default false,
    totp_secret_enc       bytea,
    totp_enabled          boolean not null default false,
    totp_last_counter     bigint,
    recovery_codes_hash   text[] not null default '{}',
    failed_login_count    integer not null default 0,
    lockout_until         timestamptz,
    security_stamp        uuid not null,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now(),
    last_login_at         timestamptz
);

create table identity_providers (
    id                uuid primary key,
    slug              text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,30}$'),
    display_name      text not null,
    authority         text not null,             -- https://idp.example.com/realms/main
    client_id         text not null,
    client_secret_enc bytea,                     -- Data Protection-encrypted; set via admin UI
    client_secret_file text,                     -- alternative: path to a mounted secret file
    scopes            text not null default 'openid profile email',
    group_claim       text not null default 'groups',
    username_claim    text not null default 'preferred_username',
    email_claim       text not null default 'email',
    auto_provision    boolean not null default true,
    require_verified_email boolean not null default true,
    enabled           boolean not null default true,
    created_at        timestamptz not null default now()
);

create table role_mappings (
    id          uuid primary key,
    provider_id uuid not null references identity_providers(id) on delete cascade,
    claim_value text not null,
    role        text not null check (role in ('admin','member')),
    priority    integer not null default 0,
    unique (provider_id, claim_value)
);

create table external_identities (
    id             uuid primary key,
    user_id        uuid not null references users(id) on delete cascade,
    provider_id    uuid not null references identity_providers(id) on delete cascade,
    subject        text not null,
    email          citext,
    email_verified boolean not null default false,
    created_at     timestamptz not null default now(),
    last_login_at  timestamptz,
    unique (provider_id, subject)
);

-- ---------------------------------------------------------------- repositories & requests
create table repositories (
    id                     uuid primary key,
    github_repo_id         bigint not null unique,
    owner                  text not null,
    name                   text not null,
    full_name              citext not null,           -- display only; NOT unique (see §6.1)
    html_url               text not null,
    description            text,
    notes                  text,                      -- admin-editable
    license_spdx           text,
    default_branch         text,
    is_archived            boolean not null default false,
    state                  text not null default 'proposed'
                           check (state in ('proposed','active','paused','removed','rejected','blocked')),
    state_reason           text,                      -- shown to all users (rejected/blocked/removed)
    architectures          text[] not null default '{}'
                           check (cardinality(architectures) <= 8),
    source_priority        integer not null default 0,
    include_prereleases    boolean not null default false,
    holdback_hours         integer not null default 0 check (holdback_hours between 0 and 720),
    asset_include_glob     text not null default '*.deb',
    asset_exclude_glob     text,
    max_asset_bytes        bigint,
    sync_interval_minutes  integer not null default 30
                           check (sync_interval_minutes between 5 and 1440),
    next_sync_at           timestamptz,
    conditional_etag       text,
    last_synced_at         timestamptz,
    last_sync_status       text,
    consecutive_failures   integer not null default 0,
    proposed_by            uuid references users(id),
    approved_by            uuid references users(id),
    approved_at            timestamptz,
    removed_at             timestamptz,
    created_at             timestamptz not null default now(),
    updated_at             timestamptz not null default now()
);
create index repositories_full_name on repositories (lower(full_name));
create index repositories_due on repositories (next_sync_at)
    where state = 'active';
create index repositories_state on repositories (state);

create table change_requests (
    id            uuid primary key,
    kind          text not null check (kind in ('add_repo','add_arch')),
    repository_id uuid not null references repositories(id),
    requested_by  uuid not null references users(id),
    architectures text[] not null check (cardinality(architectures) between 1 and 8),
    note          text check (char_length(note) <= 1000),
    status        text not null default 'pending'
                  check (status in ('pending','approved','rejected','cancelled')),
    decided_by    uuid references users(id),
    decided_at    timestamptz,
    decision_note text check (char_length(decision_note) <= 500),
    created_at    timestamptz not null default now()
);
create unique index change_requests_one_pending
    on change_requests (repository_id, requested_by, kind) where status = 'pending';
create index change_requests_status on change_requests (status, created_at);
create index change_requests_user on change_requests (requested_by, created_at desc);

-- ---------------------------------------------------------------- ingestion
create table releases (
    id                   uuid primary key,
    repository_id        uuid not null references repositories(id) on delete cascade,
    github_release_id    bigint not null,
    tag_name             text not null,
    name                 text,
    body                 text,
    is_prerelease        boolean not null default false,
    is_draft             boolean not null default false,
    published_at         timestamptz,
    html_url             text,
    download_count_total bigint not null default 0,
    observed_at          timestamptz not null default now(),
    unique (repository_id, github_release_id)
);

create table release_assets (
    id              uuid primary key,
    release_id      uuid not null references releases(id) on delete cascade,
    github_asset_id bigint not null unique,
    name            text not null,
    size_bytes      bigint not null,
    content_type    text,
    digest_sha256   text,                -- GitHub-provided, if any
    download_count  bigint not null default 0,
    source_url      text not null,
    state           text not null default 'discovered'
                    check (state in ('discovered','downloaded','parsed','excluded',
                                     'failed','quarantined')),
    excluded_reason text,                -- e.g. arch_not_selected:arm64 (re-evaluated on arch change)
    failure_reason  text,
    observed_at     timestamptz not null default now()
);
create index release_assets_release on release_assets (release_id);

create table blobs (
    id                uuid primary key,
    sha256            text not null unique,
    sha512            text not null,
    size_bytes        bigint not null,
    storage_key       text not null,
    content_type      text not null,
    is_index          boolean not null default false,
    created_at        timestamptz not null default now(),
    last_referenced_at timestamptz not null default now()
);

create table packages (
    id            uuid primary key,
    name          text not null,
    name_lower    text generated always as (lower(name)) stored unique,
    first_seen_at timestamptz not null default now()
);

create table package_variants (
    id              uuid primary key,
    package_id      uuid not null references packages(id),
    version         text not null,
    architecture    text not null check (architecture ~ '^[a-z0-9][a-z0-9-]*$'),
    channel         text not null check (channel in ('stable','prerelease')),
    control         json not null,           -- sanitised control fields, order preserved
    description     text not null,
    filename        text not null,           -- pool filename of the *current winner's* bytes
    size_bytes      bigint not null,
    sha256          text not null,
    sha512          text not null,
    blob_id         uuid not null references blobs(id),
    state           text not null default 'active'
                    check (state in ('active','quarantined','tombstoned')),
    quarantine_reason text,                  -- reserved_name | epoch | admin | ...
    publish_after   timestamptz,             -- release holdback
    first_seen_at   timestamptz not null default now(),
    published_at    timestamptz,
    unique (package_id, version, architecture),
    unique (filename)
);
create index package_variants_publish on package_variants (channel, architecture)
    where state = 'active';

create table package_sources (
    id            uuid primary key,
    variant_id    uuid not null references package_variants(id) on delete cascade,
    asset_id      uuid not null unique references release_assets(id),
    repository_id uuid not null references repositories(id) on delete cascade,
    blob_id       uuid not null references blobs(id),   -- this source's own bytes
    is_winner     boolean not null default false,
    created_at    timestamptz not null default now()
);
create unique index package_sources_one_winner
    on package_sources (variant_id) where is_winner;
create index package_sources_repo on package_sources (repository_id);

-- Immutable pool filename registry: a name is never reused with different bytes.
create table pool_files (
    component  text not null default 'main',
    filename   text not null,
    sha256     text not null,
    size_bytes bigint not null,
    created_at timestamptz not null default now(),
    primary key (component, filename)
);

-- ---------------------------------------------------------------- apt output
create table apt_suites (
    id                 uuid primary key,
    name               text not null unique check (name in ('stable','testing')),
    component          text not null default 'main',
    include_prereleases boolean not null default false,
    is_enabled         boolean not null default true,
    not_automatic      boolean not null default false,
    origin             text not null default 'RepoCuck',
    label              text not null default 'RepoCuck',
    description        text not null default 'RepoCuck curated APT repository',
    valid_until_days   integer not null default 7 check (valid_until_days between 1 and 30),
    retain_generations integer not null default 5 check (retain_generations between 2 and 50),
    retain_hours       integer not null default 48 check (retain_hours between 6 and 720)
);

create table apt_generations (
    id                 uuid primary key,
    suite_id           uuid not null references apt_suites(id),
    generation_no      bigint not null,
    status             text not null check (status in ('building','signed','superseded','failed')),
    release_blob_id    uuid references blobs(id),
    inrelease_blob_id  uuid references blobs(id),
    release_gpg_blob_id uuid references blobs(id),
    package_count      integer not null default 0,
    created_at         timestamptz not null default now(),
    activated_at       timestamptz,
    unique (suite_id, generation_no)
);

create table apt_generation_files (
    generation_id uuid not null references apt_generations(id) on delete cascade,
    path          text not null,           -- relative to /dists/<suite>/
    blob_id       uuid not null references blobs(id),
    sha256        text not null,
    size_bytes    bigint not null,
    primary key (generation_id, path)
);

-- The single source of truth for "which generation is live".
create table apt_current (
    suite_id      uuid primary key references apt_suites(id),
    generation_id uuid not null references apt_generations(id),
    updated_at    timestamptz not null default now()
);

-- ---------------------------------------------------------------- jobs/ops
create table jobs (
    id          uuid primary key,
    kind        text not null,
    payload     jsonb not null default '{}',
    dedupe_key  text,
    state       text not null default 'pending'
                check (state in ('pending','running','succeeded','failed','dead')),
    attempts    integer not null default 0,
    max_attempts integer not null default 5,
    run_after   timestamptz not null default now(),
    locked_by   text,
    locked_until timestamptz,
    last_error  text,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);
-- Only one *pending* job per key; a running job does not block enqueueing the next one
-- (the claim query refuses to start a job while another with the same key is running).
create unique index jobs_dedupe_pending on jobs (dedupe_key)
    where state = 'pending' and dedupe_key is not null;
create index jobs_ready on jobs (run_after) where state = 'pending';

create table sync_runs (
    id                uuid primary key,
    repository_id     uuid not null references repositories(id) on delete cascade,
    trigger           text not null check (trigger in ('schedule','manual','webhook','bootstrap','quarantine')),
    started_at        timestamptz not null default now(),
    finished_at       timestamptz,
    status            text not null default 'running'
                      check (status in ('running','succeeded','partial','failed')),
    releases_seen     integer not null default 0,
    assets_seen       integer not null default 0,
    assets_ingested   integer not null default 0,
    assets_excluded   integer not null default 0,
    assets_failed     integer not null default 0,
    variants_created  integer not null default 0,
    conflicts_found   integer not null default 0,
    error_category    text,
    error             text
);
create index sync_runs_repo on sync_runs (repository_id, started_at desc);

create table audit_log (
    id            bigserial primary key,
    occurred_at   timestamptz not null default now(),
    actor_user_id uuid references users(id),
    actor_label   text,
    actor_ip      inet,
    action        text not null,
    target_type   text,
    target_id     text,
    outcome       text not null default 'success'
                  check (outcome in ('success','failure','denied')),
    metadata      jsonb not null default '{}',
    correlation_id text
);
create index audit_log_time on audit_log (occurred_at desc);
create index audit_log_actor on audit_log (actor_user_id, occurred_at desc);

create table github_cache (
    cache_key  text primary key,
    etag       text,
    payload    jsonb,
    fetched_at timestamptz not null default now(),
    expires_at timestamptz
);

create table settings (
    key        text primary key,
    value      jsonb not null,
    updated_at timestamptz not null default now(),
    updated_by uuid references users(id)
);

create function deny_mutation() returns trigger language plpgsql as $$
begin
    raise exception 'table % is append-only', tg_table_name;
end $$;

create trigger audit_log_immutable
    before update or delete on audit_log
    for each row execute function deny_mutation();
