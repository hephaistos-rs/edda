//! Integration-style tests against a real (in-memory) SQLite database —
//! the pattern the pre-restructuring `access::mod` tests already used,
//! carried forward here since that's where the equivalent logic now
//! lives. See `edda-domain`'s own test module for the pure-authorization-
//! decision tests this crate deliberately doesn't duplicate (this module
//! tests persistence and schema behavior, not authorization policy).

use edda_domain::{RepoRole, Repository, RepositoryId, RepositoryOwner, User, UserId, Visibility};

use crate::{AccessTokenRepo, RepoAccessRepo, RepositoryRepo, UserRepo};

async fn insert_user(pool: &sqlx::SqlitePool, username: &str) -> UserId {
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
