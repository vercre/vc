use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use futures::{future, Stream, StreamExt};
use iroh::bytes::store::{flat, mem};
use iroh::client::{Doc, LiveEvent};
// use iroh::net::key::SecretKey;
use iroh::node;
use iroh::rpc_protocol::{
    BlobDownloadRequest, DocTicket, DownloadLocation, ProviderRequest, ProviderResponse,
    SetTagOption, ShareMode,
};
use iroh::sync::store::{fs, memory}; // Query
use iroh::sync::ContentStatus;
use iroh::ticket::BlobTicket;
use iroh::util::path::IrohPaths;
use quic_rpc::transport::flume::FlumeConnection;
use tokio_util::task::LocalPoolHandle;

// const DEF_RPC_PORT: u16 = 0x1337;

#[derive(Clone, Debug)]
pub struct Node {
    // pub node: iroh::node::Node<flat::Store>,
    pub node: iroh::node::Node<mem::Store>,
    docs: HashMap<DocType, Doc<FlumeConnection<ProviderResponse, ProviderRequest>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocType {
    Credential,
    // Stronghold,
}

impl Node {
    pub async fn new(data_root: impl Into<PathBuf>) -> Result<Self> {
        // let repo = PathBuf::from("./data");
        let repo = data_root.into();
        let flat_dir = repo.join(IrohPaths::BaoFlatStoreDir);
        let docs_dir = repo.join(IrohPaths::DocsDatabase);

        // let blob_store = flat::Store::load(&flat_dir).await?;
        // let doc_store = fs::Store::new(docs_dir)?;
        let blob_store = mem::Store::new();
        let doc_store = memory::Store::default();

        let rt = LocalPoolHandle::new(1);

        let node = node::Node::builder(blob_store, doc_store).local_pool(&rt).spawn().await?;

        Ok(Node {
            node,
            docs: HashMap::new(),
        })
    }

    pub async fn load_doc(&mut self, doc_type: DocType, ticket: &str) -> Result<()> {
        let iroh = self.node.client();
        let doc_ticket = DocTicket::from_str(ticket)?;

        // let doc = match iroh.docs.open(doc_ticket.capability.id()).await {
        //     Ok(Some(doc)) => doc,
        //     Err(_) => iroh.docs.import(doc_ticket).await?,
        //     _ => anyhow::bail!("Error opening doc"),
        // };

        let doc = iroh.docs.import(doc_ticket.clone()).await?;
        doc.start_sync(doc_ticket.nodes).await?;
        doc.share(ShareMode::Write).await?;

        self.docs.insert(doc_type, doc);

        Ok(())
    }

    pub fn credentials(&self) -> Option<&Doc<FlumeConnection<ProviderResponse, ProviderRequest>>> {
        self.docs.get(&DocType::Credential)
    }

    pub async fn events(&self) -> impl Stream<Item = String> {
        // pub async fn events(&self) -> impl Iterator<Item = String> {
        let doc = self.credentials().expect("should have credentials");
        // doc.subscribe().await

        let events = doc.subscribe().await.expect("should subscribe");

        return events.map(|event| {
            match event.unwrap() {
                LiveEvent::InsertRemote { content_status, .. } => {
                    // if content_status == ContentStatus::Complete {
                    String::from("insert remote")
                    // }
                }
                LiveEvent::InsertLocal { .. } => String::from("insert local"),
                LiveEvent::ContentReady { hash } => String::from("content ready"),
                LiveEvent::SyncFinished(sync) => String::from(format!("sync finished: {:?}", sync)),
                _ => String::from(""),
            }
        });

        // while let Some(Ok(event)) = events.next().await {
        //     match event {
        //         LiveEvent::InsertRemote { content_status, .. } => {
        //             // only update if we already have the content
        //             if content_status == ContentStatus::Complete {
        //                 println!("insert remote");
        //                 return String::from("");
        //             }
        //         }
        //         LiveEvent::InsertLocal { .. } => {
        //             println!("insert local");
        //             return String::from("");
        //         }
        //         LiveEvent::ContentReady { hash } => {
        //             println!("content ready");
        //             let bytes = iroh.blobs.read_to_bytes(hash).await.expect("should get bytes");
        //             println!("Got bytes: {:?}", bytes.len());
        //             return String::from("");
        //         }
        //         _ => {}
        //     }
        // }
    }

    // async fn import_doc(
    //     &self, ticket: DocTicket,
    // ) -> Result<Doc<FlumeConnection<ProviderResponse, ProviderRequest>>> {
    //     let iroh = self.node.client();

    //     let doc = iroh.docs.import(ticket).await?;

    //     let mut events = doc.subscribe().await?;
    //     let _ = tokio::spawn(async move {
    //         while let Some(Ok(event)) = events.next().await {
    //             match event {
    //                 LiveEvent::InsertRemote { content_status, .. } => {
    //                     // only update if we already have the content
    //                     if content_status == ContentStatus::Complete {
    //                         println!("insert remote");
    //                     }
    //                 }
    //                 LiveEvent::InsertLocal { .. } => {
    //                     println!("insert local");
    //                 }
    //                 LiveEvent::ContentReady { hash } => {
    //                     println!("content ready");
    //                     let bytes = iroh.blobs.read_to_bytes(hash).await.expect("should get bytes");
    //                     println!("Got bytes: {:?}", bytes.len());
    //                 }
    //                 _ => {}
    //             }
    //         }
    //     });

    //     Ok(doc)
    // }

    pub async fn _download_blob(&self, ticket: &str) -> Result<()> {
        let iroh = self.node.client();

        let ticket = BlobTicket::from_str(ticket)?;
        let req = BlobDownloadRequest {
            hash: ticket.hash(),
            format: ticket.format(),
            peer: ticket.node_addr().clone(),
            tag: SetTagOption::Auto,
            out: DownloadLocation::Internal,
        };

        let stream = iroh.blobs.download(req).await?;
        let _ = stream
            .for_each(|item| {
                println!("Got item: {:?}", item);
                future::ready(())
            })
            .await;

        Ok(())
    }
}
