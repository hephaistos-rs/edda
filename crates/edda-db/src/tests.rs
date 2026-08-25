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

use crate::{AccessTokenRepo, LfsRepo, RepoAccessRepo, RepositoryRepo, SshKeyRepo, UserRepo};

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
