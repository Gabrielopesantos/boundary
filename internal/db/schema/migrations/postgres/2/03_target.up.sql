begin;

  create table target_credential_type_enm (
    name text primary key
      constraint only_predefined_credential_types_allowed
      check (
        name in (
          'application',
          'ingress',
          'egress'
        )
      )
  );
  comment on table target_credential_type_enm is
    'target_credential_type_enm is an enumeration table for credential types. '
    'It contains rows for representing the application, egress, and ingress credential types.';

  insert into target_credential_type_enm (name)
  values
    ('application'),
    ('ingress'),
    ('egress');

  create table target_credential_library (
    target_id wt_public_id not null
      constraint target_fk
        references target (public_id)
        on delete cascade
        on update cascade,
    credential_library_id wt_public_id not null
      constraint credential_library_fk
        references credential_library (public_id)
        on delete cascade
        on update cascade,
    target_credential_type text not null
      constraint target_credential_type_fk
        references target_credential_type_enm (name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    primary key(target_id, credential_library_id, target_credential_type)
  );
  comment on table target_credential_library is
    'target_credential_library is a join table between the target and credential_library tables. '
    'It also contains the credential type the relationship represents.';

  create trigger default_create_time_column before insert on target_credential_library
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on target_credential_library
    for each row execute procedure immutable_columns('target_id', 'credential_library_id', 'target_credential_type', 'create_time');

commit;
