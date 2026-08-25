//! Integration-style tests against a real (in-memory) SQLite database —
//! the pattern the pre-restructuring `access::mod` tests already used,
//! carried forward here since that's where the equivalent logic now
//! lives. See `edda-domain`'s own test module for the pure-authorization-
//! decision tests this crate deliberately doesn't duplicate (this module
//! tests persistence and schema behavior, not authorization policy).

use edda_domain::{
    LfsLockId, RepoRole, Repository, RepositoryId, RepositoryOwner, SshKeyId, User, UserId,
    Visibility,
};

use crate::{
    AccessTokenRepo, AuditEventRepo, LfsRepo, OAuthIdentityRepo, RepoAccessRepo, RepositoryRepo,
    SshKeyRepo, TotpRepo, UserRepo, WebauthnRepo,
};

async fn insert_user(pool: &crate::DbPool, username: &str) -> UserId {
    let id = UserId::new();
    UserRepo::insert(pool, id, username, &format!("{username}@example.com"), "x")
        .await
        .unwrap();
    id
}

fn repo(owner: UserId, name: &str, visibility: Visibility) -> Repository {
    Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(owner),
        name: name.to_string(),
        description: None,
        visibility,
        forked_from: None,
    }
}

#[tokio::test]
async fn a_repository_name_is_only_unique_per_owner() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    RepositoryRepo::insert(&pool, &repo(alice, "shared", Visibility::Public))
        .await
        .unwrap();
    RepositoryRepo::insert(&pool, &repo(bob, "shared", Visibility::Public))
        .await
        .unwrap();

    let err = RepositoryRepo::insert(&pool, &repo(alice, "shared", Visibility::Public))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        crate::repository_repo::InsertRepositoryError::AlreadyExists(_)
    ));
}

#[tokio::test]
async fn access_grants_are_keyed_by_the_specific_repository_not_just_its_name() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let alice_repo = repo(alice, "shared", Visibility::Public);
    let bob_repo = repo(bob, "shared", Visibility::Public);
    RepositoryRepo::insert(&pool, &alice_repo).await.unwrap();
    RepositoryRepo::insert(&pool, &bob_repo).await.unwrap();

    RepoAccessRepo::grant_owner(&pool, alice_repo.id, alice)
        .await
        .unwrap();
    RepoAccessRepo::grant_owner(&pool, bob_repo.id, bob)
        .await
        .unwrap();

    assert_eq!(
        RepoAccessRepo::find(&pool, alice_repo.id, alice)
            .await
            .unwrap()
            .unwrap()
            .role,
        RepoRole::Owner
    );
    assert!(RepoAccessRepo::find(&pool, bob_repo.id, alice)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_collaborator_grant_can_be_added_and_removed_but_the_owner_grant_cannot() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let carol = insert_user(&pool, "carol").await;

    let alice_repo = repo(alice, "shared", Visibility::Private);
    RepositoryRepo::insert(&pool, &alice_repo).await.unwrap();
    RepoAccessRepo::grant_owner(&pool, alice_repo.id, alice)
        .await
        .unwrap();
    RepoAccessRepo::grant(&pool, alice_repo.id, carol, RepoRole::Write)
        .await
        .unwrap();

    assert_eq!(
        RepoAccessRepo::find(&pool, alice_repo.id, carol)
            .await
            .unwrap()
            .unwrap()
            .role,
        RepoRole::Write
    );

    let removed = RepoAccessRepo::remove_collaborator(&pool, alice_repo.id, carol)
        .await
        .unwrap();
    assert!(removed);
    assert!(RepoAccessRepo::find(&pool, alice_repo.id, carol)
        .await
        .unwrap()
        .is_none());

    // The owner grant is structurally protected — `remove_collaborator`'s
    // own `role != 'owner'` clause is what's under test here, independent
    // of any authorization-layer check.
    let removed_owner = RepoAccessRepo::remove_collaborator(&pool, alice_repo.id, alice)
        .await
        .unwrap();
    assert!(!removed_owner);
    assert_eq!(
        RepoAccessRepo::find(&pool, alice_repo.id, alice)
            .await
            .unwrap()
            .unwrap()
            .role,
        RepoRole::Owner
    );
}

#[tokio::test]
async fn deleting_a_repository_cascades_its_access_grants() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let alice_repo = repo(alice, "shared", Visibility::Private);
    RepositoryRepo::insert(&pool, &alice_repo).await.unwrap();
    RepoAccessRepo::grant_owner(&pool, alice_repo.id, alice)
        .await
        .unwrap();
    RepoAccessRepo::grant(&pool, alice_repo.id, bob, RepoRole::Write)
        .await
        .unwrap();

    RepositoryRepo::delete(&pool, alice_repo.id).await.unwrap();

    // Unlike the pre-restructuring code (which had to remember a separate
    // `access::revoke_all` call after deleting a repo), this is now
    // structurally guaranteed by `repo_access`'s `ON DELETE CASCADE`
    // foreign key — nothing in this test calls anything access-specific
    // after `delete`.
    assert!(RepoAccessRepo::find(&pool, alice_repo.id, alice)
        .await
        .unwrap()
        .is_none());
    assert!(RepoAccessRepo::find(&pool, alice_repo.id, bob)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn signup_style_username_and_email_collisions_are_reported_distinctly() {
    let pool = crate::test_pool().await;
    insert_user(&pool, "alice").await;

    let err = UserRepo::insert(
        &pool,
        UserId::new(),
        "alice",
        "someone-else@example.com",
        "x",
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        crate::user_repo::InsertUserError::UsernameTaken
    ));

    let err = UserRepo::insert(
        &pool,
        UserId::new(),
        "someone-else",
        "alice@example.com",
        "x",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, crate::user_repo::InsertUserError::EmailTaken));
}

#[tokio::test]
async fn an_access_token_authenticates_back_to_its_owning_user_and_scope() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    AccessTokenRepo::insert(
        &pool,
        edda_domain::AccessTokenId::new(),
        alice,
        "laptop",
        "deadbeef",
        &edda_domain::RepositoryScope::All,
    )
    .await
    .unwrap();

    let (user, scope): (User, edda_domain::RepositoryScope) =
        AccessTokenRepo::find_by_hash(&pool, "deadbeef")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(user.id, alice);
    assert_eq!(scope, edda_domain::RepositoryScope::All);

    assert!(AccessTokenRepo::find_by_hash(&pool, "not-a-real-hash")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn an_ssh_key_resolves_back_to_its_owning_user() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    SshKeyRepo::insert(
        &pool,
        SshKeyId::new(),
        alice,
        "SHA256:deadbeef",
        "ssh-ed25519 AAAA... laptop",
        "laptop",
    )
    .await
    .unwrap();

    let user = SshKeyRepo::find_by_fingerprint(&pool, "SHA256:deadbeef")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.id, alice);

    assert!(
        SshKeyRepo::find_by_fingerprint(&pool, "SHA256:not-registered")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_same_fingerprint_cannot_be_registered_twice() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    SshKeyRepo::insert(
        &pool,
        SshKeyId::new(),
        alice,
        "SHA256:shared",
        "ssh-ed25519 AAAA... k1",
        "k1",
    )
    .await
    .unwrap();
    let err = SshKeyRepo::insert(
        &pool,
        SshKeyId::new(),
        bob,
        "SHA256:shared",
        "ssh-ed25519 AAAA... k2",
        "k2",
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        crate::ssh_key_repo::InsertSshKeyError::FingerprintTaken
    ));
}

#[tokio::test]
async fn revoking_an_ssh_key_is_scoped_to_its_owner() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let key_id = SshKeyId::new();
    SshKeyRepo::insert(
        &pool,
        key_id,
        alice,
        "SHA256:alice-key",
        "ssh-ed25519 AAAA... k",
        "k",
    )
    .await
    .unwrap();

    // Bob can't revoke Alice's key by guessing its id.
    assert!(!SshKeyRepo::revoke(&pool, bob, key_id).await.unwrap());
    assert!(SshKeyRepo::find_by_fingerprint(&pool, "SHA256:alice-key")
        .await
        .unwrap()
        .is_some());

    assert!(SshKeyRepo::revoke(&pool, alice, key_id).await.unwrap());
    assert!(SshKeyRepo::find_by_fingerprint(&pool, "SHA256:alice-key")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn deleting_a_user_cascades_their_ssh_keys() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    SshKeyRepo::insert(
        &pool,
        SshKeyId::new(),
        alice,
        "SHA256:alice-key",
        "ssh-ed25519 AAAA... k",
        "k",
    )
    .await
    .unwrap();

    let alice_id_text = alice.to_string();
    let sql = match pool.backend {
        crate::Backend::Postgres => "DELETE FROM users WHERE id = $1",
        crate::Backend::Sqlite | crate::Backend::MySql => "DELETE FROM users WHERE id = ?",
    };
    sqlx::query(sql)
        .bind(&alice_id_text)
        .execute(&pool.any)
        .await
        .unwrap();

    assert!(SshKeyRepo::find_by_fingerprint(&pool, "SHA256:alice-key")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_fork_persists_and_round_trips_its_forked_from_pointer() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let source = repo(alice, "upstream", Visibility::Public);
    RepositoryRepo::insert(&pool, &source).await.unwrap();

    let mut fork = repo(bob, "upstream", Visibility::Public);
    fork.forked_from = Some(source.id);
    RepositoryRepo::insert_with_owner(&pool, &fork, bob)
        .await
        .unwrap();

    let found = RepositoryRepo::find_by_id(&pool, fork.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.forked_from, Some(source.id));

    let found_source = RepositoryRepo::find_by_id(&pool, source.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found_source.forked_from, None);
}

#[tokio::test]
async fn an_lfs_object_round_trips_by_repository_and_oid() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "assets", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    let oid = "a".repeat(64);
    assert!(LfsRepo::find_object(&pool, repository.id, &oid)
        .await
        .unwrap()
        .is_none());

    LfsRepo::insert_object(&pool, repository.id, &oid, 5000, "aa/aa/aaaa")
        .await
        .unwrap();

    let found = LfsRepo::find_object(&pool, repository.id, &oid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.size_bytes, 5000);
    assert_eq!(found.storage_key, "aa/aa/aaaa");

    // Content-addressed and immutable — inserting the same (repository,
    // oid) again is a harmless no-op, not a conflict error.
    LfsRepo::insert_object(&pool, repository.id, &oid, 5000, "aa/aa/aaaa")
        .await
        .unwrap();
}

#[tokio::test]
async fn an_lfs_lock_blocks_a_second_lock_on_the_same_path_until_released() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;
    let repository = repo(alice, "assets", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    let lock_id = LfsLockId::new();
    LfsRepo::create_lock(&pool, lock_id, repository.id, "asset.psd", alice)
        .await
        .unwrap();

    let err = LfsRepo::create_lock(&pool, LfsLockId::new(), repository.id, "asset.psd", bob)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        crate::lfs_repo::CreateLockError::AlreadyLocked(_)
    ));

    let locks = LfsRepo::list_locks(&pool, repository.id).await.unwrap();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].owner_id, alice);

    assert!(LfsRepo::delete_lock(&pool, lock_id).await.unwrap());
    assert!(LfsRepo::list_locks(&pool, repository.id)
        .await
        .unwrap()
        .is_empty());

    // Now that it's released, someone else can take the same path.
    LfsRepo::create_lock(&pool, LfsLockId::new(), repository.id, "asset.psd", bob)
        .await
        .unwrap();
}

#[tokio::test]
async fn an_oauth_identity_resolves_back_to_its_linked_user() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    OAuthIdentityRepo::insert(
        &pool,
        edda_domain::OAuthIdentityId::new(),
        alice,
        "test-idp",
        "sub-123",
    )
    .await
    .unwrap();

    let identity = OAuthIdentityRepo::find_by_provider_subject(&pool, "test-idp", "sub-123")
        .await
        .unwrap()
        .expect("identity round-trips");
    assert_eq!(identity.user_id, alice);

    assert!(
        OAuthIdentityRepo::find_by_provider_subject(&pool, "test-idp", "no-such-subject")
            .await
            .unwrap()
            .is_none()
    );

    let identities = OAuthIdentityRepo::list_for_user(&pool, alice)
        .await
        .unwrap();
    assert_eq!(identities.len(), 1);

    assert!(OAuthIdentityRepo::delete(&pool, alice, identity.id)
        .await
        .unwrap());
    assert!(OAuthIdentityRepo::list_for_user(&pool, alice)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_totp_secret_is_not_activated_until_activate_is_called() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    assert!(!TotpRepo::is_activated(&pool, alice).await.unwrap());

    TotpRepo::upsert_secret(&pool, alice, b"ciphertext-bytes")
        .await
        .unwrap();
    assert!(!TotpRepo::is_activated(&pool, alice).await.unwrap());

    let (stored, activated_at) = TotpRepo::find_by_user(&pool, alice)
        .await
        .unwrap()
        .expect("secret round-trips");
    assert_eq!(stored, b"ciphertext-bytes");
    assert!(activated_at.is_none());

    TotpRepo::activate(&pool, alice).await.unwrap();
    assert!(TotpRepo::is_activated(&pool, alice).await.unwrap());
}

#[tokio::test]
async fn a_totp_recovery_code_can_only_be_consumed_once() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    TotpRepo::replace_recovery_codes(&pool, alice, &["hash-a".to_string(), "hash-b".to_string()])
        .await
        .unwrap();

    assert!(TotpRepo::consume_recovery_code(&pool, alice, "hash-a")
        .await
        .unwrap());
    assert!(!TotpRepo::consume_recovery_code(&pool, alice, "hash-a")
        .await
        .unwrap());
    assert!(
        !TotpRepo::consume_recovery_code(&pool, alice, "no-such-hash")
            .await
            .unwrap()
    );
    assert!(TotpRepo::consume_recovery_code(&pool, alice, "hash-b")
        .await
        .unwrap());
}

#[tokio::test]
async fn disabling_totp_removes_the_secret_and_every_recovery_code() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    TotpRepo::upsert_secret(&pool, alice, b"ciphertext-bytes")
        .await
        .unwrap();
    TotpRepo::replace_recovery_codes(&pool, alice, &["hash-a".to_string()])
        .await
        .unwrap();
    TotpRepo::activate(&pool, alice).await.unwrap();

    TotpRepo::delete(&pool, alice).await.unwrap();

    assert!(TotpRepo::find_by_user(&pool, alice)
        .await
        .unwrap()
        .is_none());
    assert!(!TotpRepo::consume_recovery_code(&pool, alice, "hash-a")
        .await
        .unwrap());
}

#[tokio::test]
async fn a_webauthn_credential_round_trips_and_can_be_revoked_by_its_owner() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let id = edda_domain::WebauthnCredentialId::new();
    WebauthnRepo::insert(&pool, id, alice, "laptop", "{\"fake\":\"passkey\"}")
        .await
        .unwrap();

    let creds = WebauthnRepo::list_for_user(&pool, alice).await.unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].label, "laptop");
    assert!(creds[0].last_used_at.is_none());

    WebauthnRepo::update_passkey(&pool, id, "{\"fake\":\"updated\"}")
        .await
        .unwrap();
    let creds = WebauthnRepo::list_for_user(&pool, alice).await.unwrap();
    assert!(creds[0].last_used_at.is_some());

    // Bob can't revoke Alice's credential by guessing its id.
    assert!(!WebauthnRepo::delete(&pool, bob, id).await.unwrap());
    assert!(WebauthnRepo::delete(&pool, alice, id).await.unwrap());
}

#[tokio::test]
async fn audit_events_list_most_recent_first() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    AuditEventRepo::insert(
        &pool,
        edda_domain::AuditEventId::new(),
        "auth.login.success",
        Some(&alice.to_string()),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    AuditEventRepo::insert(
        &pool,
        edda_domain::AuditEventId::new(),
        "auth.token.create",
        Some(&alice.to_string()),
        Some("access_token"),
        None,
        Some("{\"name\":\"ci\"}"),
    )
    .await
    .unwrap();

    let events = AuditEventRepo::list_recent(&pool, 10).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, "auth.token.create");
    assert_eq!(events[1].event_type, "auth.login.success");
}
