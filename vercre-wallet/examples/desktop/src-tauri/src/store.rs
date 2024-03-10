use futures::StreamExt;
use serde_json::Value;
use tauri::async_runtime::{block_on, spawn};
use tauri::Manager;
use vercre_wallet::store::{StoreRequest, StoreResponse};

use crate::iroh::DocType;
use crate::{error, IrohState};

// Iroh document ticket for the credential store
const VC_STORE: &str = "docaaacbp4ivplq3xf7krm3y5zybzjv2ha56qvhpfiykjjc6iukdifgoyihafk62aofuwwwu5zb5ocvzj5v3rtqt6siglyuhoxhqtu4fxravvoteajcnb2hi4dthixs65ltmuys2mjomrsxe4bonfzg62bonzsxi53pojvs4lydaac2cyt22erablaraaa5ciqbfiaqj7ya6cbpuaaaaaaaaaaaahjce";

// initialise the credential store on the Iroh node
pub fn init(handle: tauri::AppHandle) -> anyhow::Result<()> {
    block_on(async {
        let state = handle.state::<IrohState>();
        let node = state.node.lock().await;
        let doc = node.join_doc(DocType::Credential, VC_STORE).await?;

        let handle2 = handle.clone();
        let jh = spawn(async move {
            while let Some(event) = doc.events().await.next().await {
                println!("{event}");
                super::get_list(handle2.clone()).await.expect("should process event");
            }
        });

        let mut events = state.events.lock().await;
        if let Some(handle) = events.take() {
            handle.abort();
        }
        *events = Some(jh);

        Ok(())
    })
}

pub async fn request<R>(
    op: &StoreRequest, app_handle: &tauri::AppHandle<R>,
) -> Result<StoreResponse, error::Error>
where
    R: tauri::Runtime,
{
    let state = app_handle.state::<IrohState>();
    let node = state.node.lock().await;

    match op {
        StoreRequest::Add(_id, value) => {
            // with_store(app_handle.clone(), stores, path.clone(), |store| {
            //     let val = serde_json::from_slice(value).unwrap();
            //     log::info!("Storing: {} => {:?} into {}", id, val, path.clone().display());
            //     store.insert(id.to_string(), val)?;
            //     store.save()
            // })?;
            node.add_doc(DocType::Credential,value).await?;

            Ok(StoreResponse::Ok)
        }
        StoreRequest::List => {
            let doc = node.doc(&DocType::Credential).unwrap();
            let entries = doc.entries().await?;
            let mut values = vec![];

            for entry in entries {
                let val: Value = serde_json::from_slice(&entry).expect("should be json");
                values.push(val);
            }
            let values_vec = serde_json::to_vec(&values).unwrap();
            Ok(StoreResponse::List(values_vec))
        }
        StoreRequest::Delete(_id) => {
            // with_store(app_handle.clone(), stores, path, |store| {
            //     store.delete(id)?;
            //     store.save()
            // })?;
            Ok(StoreResponse::Ok)
        }
    }
}
