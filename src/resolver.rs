use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::{Name, TokioAsyncResolver};

use std::io;

pub fn new(config: ResolverConfig, options: ResolverOpts) -> io::Result<TokioAsyncResolver> {
    Ok(TokioAsyncResolver::tokio(config, options)?)
}

pub fn system() -> io::Result<TokioAsyncResolver> {
    Ok(TokioAsyncResolver::tokio_from_system_conf()?)
}

pub fn default_opts() -> ResolverOpts {
    ResolverOpts {
        validate: true,
        use_hosts_file: true,
        ..Default::default()
    }
}

fn get_hostname() -> io::Result<Name> {
    let hostname = hostname::get()?
        .into_string()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(Name::from_utf8(hostname)?)
}

pub fn google(options: ResolverOpts) -> io::Result<TokioAsyncResolver> {
    let mut config = ResolverConfig::google();
    config.set_domain(get_hostname()?.base_name());
    new(config, options)
}

pub fn google_https(options: ResolverOpts) -> io::Result<TokioAsyncResolver> {
    let domain = get_hostname()?.base_name();
    let config = ResolverConfig::from_parts(
        Some(domain.clone()),
        vec![domain],
        NameServerConfigGroup::google_https(),
    );
    new(config, options)
}

pub fn cloudflare(options: ResolverOpts) -> io::Result<TokioAsyncResolver> {
    let mut config = ResolverConfig::cloudflare();
    config.set_domain(get_hostname()?.base_name());
    new(config, options)
}

pub fn cloudflare_tls(options: ResolverOpts) -> io::Result<TokioAsyncResolver> {
    let mut config = ResolverConfig::cloudflare_tls();
    config.set_domain(get_hostname()?.base_name());
    new(config, options)
}

pub fn cloudflare_https(options: ResolverOpts) -> io::Result<TokioAsyncResolver> {
    let mut config = ResolverConfig::cloudflare_https();
    config.set_domain(get_hostname()?.base_name());
    new(config, options)
}

pub fn quad9(options: ResolverOpts) -> io::Result<TokioAsyncResolver> {
    let mut config = ResolverConfig::quad9();
    config.set_domain(get_hostname()?.base_name());
    new(config, options)
}

pub fn quad9_tls(options: ResolverOpts) -> io::Result<TokioAsyncResolver> {
    let mut config = ResolverConfig::quad9_tls();
    config.set_domain(get_hostname()?.base_name());
    new(config, options)
}
