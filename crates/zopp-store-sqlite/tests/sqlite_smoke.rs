use zopp_storage::{
    CreateEnvParams, CreateProjectParams, CreateUserParams, CreateWorkspaceParams, EnvName,
    ProjectName, Store, StoreError, UserId,
};
use zopp_store_sqlite::SqliteStore;

fn workspace_params(owner_user_id: UserId) -> CreateWorkspaceParams {
    CreateWorkspaceParams {
        name: "test-workspace".to_string(),
        owner_user_id,
        kdf_salt: b"0123456789abcdef".to_vec(),
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    }
}

#[tokio::test]
async fn end_to_end_happy_path_and_updates() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user first
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    // workspace + project + env
    let ws = s
        .create_workspace(&workspace_params(user_id))
        .await
        .unwrap();
    let p = ProjectName("p1".into());
    let e = EnvName("prod".into());
    s.create_project(&CreateProjectParams {
        workspace_id: ws.clone(),
        name: p.clone(),
    })
    .await
    .unwrap();

    let dek_wrapped = vec![1, 2, 3, 4];
    let dek_nonce = vec![9u8; 24];
    s.create_env(&CreateEnvParams {
        workspace_id: ws.clone(),
        project_name: p.clone(),
        env_name: e.clone(),
        dek_wrapped: dek_wrapped.clone(),
        dek_nonce: dek_nonce.clone(),
    })
    .await
    .unwrap();

    // env wrap round-trip
    let (got_wrap, got_nonce) = s.get_env_wrap(&ws, &p, &e).await.unwrap();
    assert_eq!(got_wrap, dek_wrapped);
    assert_eq!(got_nonce, dek_nonce);

    // secret upsert + read
    let k = "DB_PASSWORD";
    let nonce = vec![7u8; 24];
    let ct1 = vec![8u8; 32];

    s.upsert_secret(&ws, &p, &e, k, &nonce, &ct1).await.unwrap();
    let row1 = s.get_secret(&ws, &p, &e, k).await.unwrap();
    assert_eq!(row1.nonce, nonce);
    assert_eq!(row1.ciphertext, ct1);

    // overwrite same key: new ciphertext should appear
    let ct2 = vec![42u8; 48];
    s.upsert_secret(&ws, &p, &e, k, &nonce, &ct2).await.unwrap();
    let row2 = s.get_secret(&ws, &p, &e, k).await.unwrap();
    assert_eq!(
        row2.ciphertext, ct2,
        "upsert should update the value in-place"
    );

    // add a few more keys out-of-order and verify sorted listing
    s.upsert_secret(&ws, &p, &e, "z_last", &nonce, b"Z")
        .await
        .unwrap();
    s.upsert_secret(&ws, &p, &e, "a_first", &nonce, b"A")
        .await
        .unwrap();
    s.upsert_secret(&ws, &p, &e, "m_middle", &nonce, b"M")
        .await
        .unwrap();

    let keys = s.list_secret_keys(&ws, &p, &e).await.unwrap();
    assert_eq!(keys, vec!["DB_PASSWORD", "a_first", "m_middle", "z_last"]);
}

#[tokio::test]
async fn workspace_isolation_end_to_end() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws1 = s
        .create_workspace(&workspace_params(user_id.clone()))
        .await
        .unwrap();
    let ws2 = s
        .create_workspace(&workspace_params(user_id))
        .await
        .unwrap();

    let p = ProjectName("app".into());
    let e = EnvName("prod".into());

    // same names in both workspaces
    s.create_project(&CreateProjectParams {
        workspace_id: ws1.clone(),
        name: p.clone(),
    })
    .await
    .unwrap();
    s.create_env(&CreateEnvParams {
        workspace_id: ws1.clone(),
        project_name: p.clone(),
        env_name: e.clone(),
        dek_wrapped: vec![1],
        dek_nonce: vec![9; 24],
    })
    .await
    .unwrap();

    s.create_project(&CreateProjectParams {
        workspace_id: ws2.clone(),
        name: p.clone(),
    })
    .await
    .unwrap();
    s.create_env(&CreateEnvParams {
        workspace_id: ws2.clone(),
        project_name: p.clone(),
        env_name: e.clone(),
        dek_wrapped: vec![2],
        dek_nonce: vec![9; 24],
    })
    .await
    .unwrap();

    // only write secret in ws1
    s.upsert_secret(&ws1, &p, &e, "TOKEN", &[7; 24], &[1; 8])
        .await
        .unwrap();

    // ws2 cannot read ws1’s data
    let err = s.get_secret(&ws2, &p, &e, "TOKEN").await.unwrap_err();
    matches!(err, StoreError::NotFound);
}

#[tokio::test]
async fn common_error_mapping_paths() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id))
        .await
        .unwrap();
    let p = ProjectName("dup".into());

    // Duplicate project → AlreadyExists
    s.create_project(&CreateProjectParams {
        workspace_id: ws.clone(),
        name: p.clone(),
    })
    .await
    .unwrap();
    let err = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: p.clone(),
        })
        .await
        .unwrap_err();
    matches!(err, StoreError::AlreadyExists);

    // Reading a non-existent secret → NotFound
    let e = EnvName("missing-env".into());
    // env doesn't exist yet, so this should not be found
    let err = s.get_secret(&ws, &p, &e, "NOPE").await.unwrap_err();
    matches!(err, StoreError::NotFound);
}
