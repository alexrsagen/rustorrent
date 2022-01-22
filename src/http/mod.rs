pub mod resolver;
use resolver::AsyncHyperResolver;

pub mod query_string;

use crate::error::{Error, HttpProto, InvalidProto};

use async_compression::tokio::bufread::GzipDecoder;
use bytes::Bytes;
use futures_core::stream::Stream;
use futures_util::stream::{StreamExt, TryStreamExt};
use hyper::client::{Client, HttpConnector};
use hyper::header::CONTENT_ENCODING;
use hyper::{Body, Request, Response, Uri};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};

const EXTERNAL_IP_ENDPOINTS: [&str; 4] = [
    "https://ip.kitcloud.no",
    "https://icanhazip.com",
    "https://api64.ipify.org",
    "https://ident.me",
];

const EXTERNAL_IPV4_ENDPOINTS: [&str; 4] = [
    "https://ipv4.kitcloud.no/raw",
    "https://ipv4.icanhazip.com",
    "https://api.ipify.org",
    "http://ipv4.ident.me",
];

const EXTERNAL_IPV6_ENDPOINTS: [&str; 4] = [
    "https://ipv6.kitcloud.no/raw",
    "https://ipv6.icanhazip.com",
    "https://api6.ipify.org",
    "http://ipv6.ident.me",
];

struct IoStream<'a>(&'a mut hyper::Body);

impl<'a> Stream for IoStream<'a> {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match futures_core::ready!(Pin::new(&mut self.0).poll_next(cx)) {
            Some(Ok(chunk)) => Poll::Ready(Some(Ok(chunk))),
            Some(Err(err)) => Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::Other, err)))),
            None => Poll::Ready(None),
        }
    }
}

fn client(resolver: AsyncHyperResolver) -> Client<HttpConnector<AsyncHyperResolver>> {
    let connector = HttpConnector::new_with_resolver(resolver);
    Client::builder().build(connector)
}

fn tls_client(
    resolver: AsyncHyperResolver,
) -> Client<HttpsConnector<HttpConnector<AsyncHyperResolver>>> {
    let mut connector = HttpConnector::new_with_resolver(resolver);
    connector.enforce_http(false);
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_webpki_roots()
        .with_no_client_auth();
    let connector = (connector, config).into();
    Client::builder().build(connector)
}

pub struct DualSchemeClient {
    client: Client<HttpConnector<AsyncHyperResolver>>,
    tls_client: Client<HttpsConnector<HttpConnector<AsyncHyperResolver>>>,
}

impl DualSchemeClient {
    pub fn new_with_resolver(resolver: AsyncHyperResolver) -> Self {
        let client = client(resolver.clone());
        let tls_client = tls_client(resolver);
        Self { client, tls_client }
    }

    pub async fn request(&self, req: Request<Body>) -> Result<Response<Body>, Error> {
        match req.uri().scheme_str() {
            Some(scheme) => match scheme {
                "https" => Ok(self.tls_client.request(req).await?),
                "http" => Ok(self.client.request(req).await?),
                _ => Err(Error::ProtoInvalid(InvalidProto::Http(HttpProto::Other(
                    String::from(scheme),
                )))),
            },
            None => Err(Error::ProtoInvalid(InvalidProto::Http(HttpProto::Unknown))),
        }
    }

    pub async fn get_external_ip(&self) -> Result<IpAddr, Error> {
        let mut last_error: Option<Error> = None;
        for endpoint in &EXTERNAL_IP_ENDPOINTS {
            match self.get_string(&Uri::from_static(endpoint)).await {
                Ok(bodystr) => match bodystr.parse::<IpAddr>() {
                    Ok(ip) => return Ok(ip),
                    Err(e) => {
                        last_error = Some(e.into());
                        continue;
                    }
                },
                Err(e) => last_error = Some(e),
            }
        }
        Err(Error::PublicIpLookupFailed(match last_error {
            Some(e) => format!("no endpoints available (last error: {})", e),
            None => String::from("no endpoints available"),
        }))
    }

    pub async fn get_external_ipv4(&self) -> Result<Ipv4Addr, Error> {
        let mut last_error: Option<Error> = None;
        for endpoint in &EXTERNAL_IPV4_ENDPOINTS {
            match self.get_string(&Uri::from_static(endpoint)).await {
                Ok(bodystr) => match bodystr.parse::<Ipv4Addr>() {
                    Ok(ip) => return Ok(ip),
                    Err(e) => {
                        last_error = Some(e.into());
                        continue;
                    }
                },
                Err(e) => last_error = Some(e),
            }
        }
        Err(Error::PublicIpLookupFailed(match last_error {
            Some(e) => format!("no endpoints available (last error: {})", e),
            None => String::from("no endpoints available"),
        }))
    }

    pub async fn get_external_ipv6(&self) -> Result<Ipv6Addr, Error> {
        let mut last_error: Option<Error> = None;
        for endpoint in &EXTERNAL_IPV6_ENDPOINTS {
            match self.get_string(&Uri::from_static(endpoint)).await {
                Ok(bodystr) => match bodystr.parse::<Ipv6Addr>() {
                    Ok(ip) => return Ok(ip),
                    Err(e) => {
                        last_error = Some(e.into());
                        continue;
                    }
                },
                Err(e) => last_error = Some(e),
            }
        }
        Err(Error::PublicIpLookupFailed(match last_error {
            Some(e) => format!("no endpoints available (last error: {})", e),
            None => String::from("no endpoints available"),
        }))
    }

    pub async fn get(&self, uri: &Uri) -> Result<Response<Body>, Error> {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("Accept-Encoding", "gzip")
            .body(Body::empty())?;
        self.request(req).await
    }

    pub async fn get_string(&self, uri: &Uri) -> Result<String, Error> {
        let mut res = self.get(uri).await?;
        let body = read_body(&mut res).await?;
        Ok(String::from_utf8(body)?)
    }
}

async fn read_body_gzip(res: &mut Response<Body>) -> Result<Vec<u8>, Error> {
    let mut stream = tokio_util::codec::FramedRead::new(
        GzipDecoder::new(tokio_util::io::StreamReader::new(IoStream(res.body_mut()))),
        tokio_util::codec::BytesCodec::new(),
    )
    .map_ok(|bytes| bytes.freeze());
    let mut buffer = Vec::new();
    while let Some(chunk) = stream.next().await {
        let mut chunk = chunk?.to_vec();
        buffer.append(&mut chunk);
    }
    Ok(buffer)
}

async fn read_body_uncompressed(res: &mut Response<Body>) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    while let Some(chunk) = res.body_mut().next().await {
        let mut chunk = chunk?.to_vec();
        buffer.append(&mut chunk);
    }
    Ok(buffer)
}

pub async fn read_body(res: &mut Response<Body>) -> Result<Vec<u8>, Error> {
    if res.headers().contains_key(CONTENT_ENCODING) {
        let encodings: Vec<&str> = res.headers()[CONTENT_ENCODING]
            .to_str()?
            .split(',')
            .into_iter()
            .map(|encoding| encoding.trim())
            .collect();
        if encodings.len() == 1 {
            match encodings[0] {
                "gzip" => Ok(read_body_gzip(res).await?),
                "identity" => Ok(read_body_uncompressed(res).await?),
                _ => Err(Error::HttpEncodingInvalid),
            }
        } else {
            Err(Error::HttpEncodingInvalid)
        }
    } else {
        Ok(read_body_uncompressed(res).await?)
    }
}
