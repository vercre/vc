use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use futures::{Stream, StreamExt, TryStreamExt};
use iroh::bytes::store::flat;
use iroh::client::LiveEvent;
use iroh::node;
use iroh::rpc_protocol::{DocTicket, ProviderRequest, ProviderResponse};
use iroh::sync::store::{fs, Query};
use iroh::sync::ContentStatus;
use iroh::util::path::IrohPaths;
use quic_rpc::transport::flume::FlumeConnection;
// use tokio_util::bytes::Bytes;
use tokio_util::task::LocalPoolHandle;

// const DEF_RPC_PORT: u16 = 0x1337;

#[derive(Clone, Debug)]
pub struct Node {
    node: iroh::node::Node<flat::Store>,
    docs: HashMap<DocType, Doc>,
}

#[derive(Clone, Debug)]
pub struct Doc {
    doc: iroh::client::Doc<FlumeConnection<ProviderResponse, ProviderRequest>>,
    iroh: iroh::client::mem::Iroh,
}

impl Doc {
    pub async fn entries(&self) -> Result<Vec<Vec<u8>>> {
        let mut entries = self.doc.get_many(Query::single_latest_per_key()).await?;

        let mut vcs = Vec::new();
        while let Some(entry) = entries.try_next().await? {
            match self.iroh.blobs.read_to_bytes(entry.content_hash()).await {
                Ok(bytes) => {
                    vcs.push(bytes.to_vec());
                }
                Err(e) => {
                    println!("Error getting entry {entry:?}: {e}");
                }
            };
        }

        Ok(vcs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocType {
    Credential,
    // Stronghold,
}

impl Node {
    pub async fn new(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let repo = data_dir.into();
        let blob_dir = repo.join(IrohPaths::BaoFlatStoreDir);
        let docs_dir = repo.join(IrohPaths::DocsDatabase);

        let blob_store = flat::Store::load(&blob_dir).await?;
        let doc_store = fs::Store::new(docs_dir)?;
        // let blob_store = mem::Store::new();
        // let doc_store = memory::Store::default();

        let rt = LocalPoolHandle::new(1);
        let node = node::Node::builder(blob_store, doc_store)
            // .peers_data_path(blob_dir)
            .local_pool(&rt)
            .spawn()
            .await?;

        Ok(Node {
            node,
            docs: HashMap::new(),
        })
    }

    pub async fn join_doc(&mut self, doc_type: DocType, ticket: &str) -> Result<()> {
        let iroh = self.node.client();

        let doc_ticket = DocTicket::from_str(ticket)?;
        let doc = iroh.docs.import(doc_ticket.clone()).await?;
        doc.start_sync(doc_ticket.nodes).await?;

        self.docs.insert(doc_type, Doc { doc, iroh });

        Ok(())
    }

    pub fn doc(&self, doc_type: DocType) -> Option<&Doc> {
        self.docs.get(&doc_type)
    }

    pub async fn events(&self) -> impl Stream<Item = String> {
        let doc = self.docs.get(&DocType::Credential).unwrap();
        let events = doc.doc.subscribe().await.expect("should subscribe");

        events.map(|event| {
            let event = event.expect("should get event");
            match event {
                LiveEvent::InsertRemote { content_status, .. } => match content_status {
                    ContentStatus::Complete => String::from("remote added"),
                    ContentStatus::Missing => String::from("remote deleted"),
                    _ => String::from("insert remote"),
                },
                LiveEvent::InsertLocal { .. } => String::from("insert local"),
                LiveEvent::ContentReady { .. } => String::from("content ready"),
                LiveEvent::SyncFinished(sync) => String::from(format!("sync finished: {:?}", sync)),
                _ => String::from(format!("other event: {:?}", event)),
            }
        })
    }

    // pub async fn download_blob(&self, ticket: &str) -> Result<()> {
    //     let iroh = self.node.client();

    //     let ticket = BlobTicket::from_str(ticket)?;
    //     let req = BlobDownloadRequest {
    //         hash: ticket.hash(),
    //         format: ticket.format(),
    //         peer: ticket.node_addr().clone(),
    //         tag: SetTagOption::Auto,
    //         out: DownloadLocation::Internal,
    //     };

    //     let stream = iroh.blobs.download(req).await?;
    //     let _ = stream
    //         .for_each(|item| {
    //             println!("Got item: {:?}", item);
    //             future::ready(())
    //         })
    //         .await;

    //     Ok(())
    // }
}
