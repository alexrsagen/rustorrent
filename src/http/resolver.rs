use hyper::client::connect::dns::Name;
use hyper::service::Service;
use trust_dns_resolver::TokioAsyncResolver;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug, Clone)]
pub struct AsyncHyperResolver(TokioAsyncResolver);

impl From<TokioAsyncResolver> for AsyncHyperResolver {
    fn from(resolver: TokioAsyncResolver) -> Self {
        Self(resolver)
    }
}

impl Service<Name> for AsyncHyperResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Error = io::Error;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let resolver = self.0.clone();
        Box::pin((|| async move {
            Ok(resolver
                .lookup_ip(name.as_str())
                .await?
                .iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect::<Vec<SocketAddr>>()
                .into_iter())
        })())
    }
}
