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
pub fn init(handle: &tauri::AppHandle) -> anyhow::Result<()> {
    block_on(async {
        let state = handle.state::<IrohState>();
        let doc = state.node.lock().await.join_doc(DocType::Credential, VC_STORE).await?;

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
        drop(events);

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
    let doc = state.node.lock().await.doc(DocType::Credential).unwrap();

    match op {
        StoreRequest::Add(id, value) => {
            doc.add_entry(id.to_owned(), value.to_owned()).await?;
            Ok(StoreResponse::Ok)
        }
        StoreRequest::List => {
            let entries = doc.entries().await?;
            // let mut values = vec![];

            let values = entries
                .iter()
                .map(|e| serde_json::from_slice::<Value>(e).expect("should be json"))
                .collect::<Vec<Value>>();

            // for entry in entries {
            //     let val: Value = serde_json::from_slice(&entry).expect("should be json");
            //     values.push(val);
            // }
            let values_vec = serde_json::to_vec(&values).unwrap();
            Ok(StoreResponse::List(values_vec))
        }
        StoreRequest::Delete(id) => {
            doc.delete_entry(id.to_owned()).await?;
            Ok(StoreResponse::Ok)
        }
    }
}
