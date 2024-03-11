use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use futures::{future, Stream, StreamExt, TryStreamExt};
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

    #[allow(dead_code)]
    pub async fn create_doc(&self, doc_type: DocType, key: String, value: Vec<u8>) -> Result<Doc> {
        let iroh = self.node.client();

        let iroh_doc = iroh.docs.create().await?;
        let author = iroh.authors.create().await?;
        iroh_doc.set_bytes(author, key, value).await?;

        let doc = Doc { doc: iroh_doc, iroh };
        self.docs.lock().expect("should lock").insert(doc_type, doc.clone());

        Ok(doc)
    }

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

// #[derive(Debug, Eq, PartialEq)]
// pub enum DocEvent {
//     Updated,
//     Error(String),
// }

impl Doc {
    pub async fn add_entry(&self, key: String, value: Vec<u8>) -> Result<()> {
        let author = self.iroh.authors.create().await?;
        self.doc.set_bytes(author, key, value).await.map(|_| ())
    }

    pub async fn delete_entry(&self, key: String) -> Result<()> {
        let author = self.iroh.authors.create().await?;
        self.doc.del(author, key).await.map(|_| ())
    }

    pub async fn entries(&self) -> Result<Vec<Vec<u8>>> {
        let mut entries = self.doc.get_many(Query::single_latest_per_key()).await?;

        let mut vcs = Vec::new();
        while let Some(entry) = entries.try_next().await? {
            match self.iroh.blobs.read_to_bytes(entry.content_hash()).await {
                Ok(bytes) => vcs.push(bytes.to_vec()),
                Err(e) => println!("Error getting entry {entry:?}: {e}"),
            };
        }

        Ok(vcs)
    }

    // Filter document events to retain only remote events, mapping the result to
    // ()
    // pub async fn updates(&self) -> impl Stream<Item = DocEvent> {
    pub async fn updates(&self) -> impl Stream<Item = ()> {
        self.doc
            .subscribe()
            .await
            .expect("should subscribe")
            // filter out uninteresting events
            .filter(|event| {
                // debug!("filter: {event:?}");
                match event {
                    Ok(LiveEvent::InsertRemote { content_status, .. }) => match content_status {
                        ContentStatus::Complete | ContentStatus::Missing => future::ready(true), // doc set,  doc del
                        ContentStatus::Incomplete => future::ready(false),
                    },
                    Err(e) => {
                        println!("Error event: {event:?}: {e}");
                        future::ready(true)
                    }
                    _ => future::ready(false),
                }
            })
            .map(|_| ())

        // .map(|event| {
        //     debug!("map: {event:?}");
        //     match event {
        //         Ok(_) => DocEvent::Updated,
        //         Err(e) => DocEvent::Error(format!("error: {e}")),
        //     }
        // })
    }
}
