use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

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
use tokio_util::task::LocalPoolHandle;

// const DEF_RPC_PORT: u16 = 0x1337;

#[derive(Clone, Debug)]
pub struct Node {
    node: iroh::node::Node<flat::Store>,
    docs: Arc<Mutex<HashMap<DocType, Doc>>>,
}

#[derive(Clone, Debug)]
pub struct Doc {
    doc: iroh::client::Doc<FlumeConnection<ProviderResponse, ProviderRequest>>,
    iroh: iroh::client::mem::Iroh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocType {
    Credential,
    // Stronghold,
}

impl Node {
    pub async fn new(data_dir: impl Into<PathBuf> + Send) -> Result<Self> {
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

        Ok(Self {
            node,
            docs: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    // pub async fn add_doc(&self, doc_type: DocType, key: String, value: Vec<u8>) -> Result<Doc> {
    //     let iroh = self.node.client();

    //     let Some(doc) = self.doc(&doc_type) else {
    //         panic!("doc not found");
    //         // let iroh_doc = iroh.docs.create().await?;
    //         // let doc = Doc { doc: iroh_doc, iroh };
    //         // self.docs.lock().expect("should lock").insert(doc_type, doc.clone());
    //         // doc
    //     };

    //     let author = iroh.authors.create().await?;
    //     let iroh_doc = &doc.doc;
    //     iroh_doc.set_bytes(author, key.to_owned(), value).await?;

    //     Ok(doc)
    // }

    pub async fn join_doc(&self, doc_type: DocType, ticket: &str) -> Result<Doc> {
        let iroh = self.node.client();
        println!("join_doc: {:?}", iroh.authors.list().await?.try_next().await?);

        let doc_ticket = DocTicket::from_str(ticket)?;
        let iroh_doc = iroh.docs.import(doc_ticket.clone()).await?;
        iroh_doc.start_sync(doc_ticket.nodes).await?;

        let doc = Doc { doc: iroh_doc, iroh };
        self.docs.lock().expect("should lock").insert(doc_type, doc.clone());

        Ok(doc)
    }

    pub fn doc(&self, doc_type: DocType) -> Option<Doc> {
        self.docs.lock().expect("should lock").get(&doc_type).cloned()
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

    pub async fn add_entry(&self, key: String, value: Vec<u8>) -> Result<()> {
        let author = self.iroh.authors.create().await?;
        let iroh_doc = &self.doc;
        iroh_doc.set_bytes(author, key, value).await?;

        Ok(())
    }

    pub async fn delete_entry(&self, key: String) -> Result<()> {
        let author = self.iroh.authors.create().await?;
        let iroh_doc = &self.doc;
        iroh_doc.del(author, key).await?;

        Ok(())
    }

    pub async fn events(&self) -> impl Stream<Item = String> {
        let events = self.doc.subscribe().await.expect("should subscribe");

        events.map(|event| {
            let event = event.expect("should get event");
            match event {
                LiveEvent::InsertRemote { content_status, .. } => match content_status {
                    ContentStatus::Complete => String::from("remote added"),
                    ContentStatus::Missing => String::from("remote deleted"),
                    ContentStatus::Incomplete => String::from("insert remote"),
                },
                LiveEvent::InsertLocal { .. } => String::from("insert local"),
                LiveEvent::ContentReady { .. } => String::from("content ready"),
                LiveEvent::SyncFinished(sync) => format!("sync finished: {sync:?}"),
                _ => format!("other event: {event:?}"),
            }
        })
    }
}
