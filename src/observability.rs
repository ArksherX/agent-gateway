use std::net::SocketAddr;
use std::sync::OnceLock;

use anyhow::Context;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::ObservabilityConfig;

static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

pub fn init(config: &ObservabilityConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    let json_layer = tracing_subscriber::fmt::layer().json();

    let otel_layer = if let Some(ref endpoint) = config.otlp_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .context("building OTLP span exporter")?;

        let resource = Resource::builder_empty()
            .with_attribute(KeyValue::new("service.name", "agent_gateway"))
            .build();

        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();

        let tracer = provider.tracer("agent_gateway");
        global::set_tracer_provider(provider.clone());
        let _ = TRACER_PROVIDER.set(provider);

        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(json_layer)
        .with(otel_layer)
        .try_init()
        .context("initializing tracing subscriber")?;

    if let Some(ref bind) = config.metrics_bind {
        let addr: SocketAddr = bind
            .parse()
            .with_context(|| format!("invalid metrics_bind: {bind}"))?;

        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(addr)
            .install()
            .context("installing Prometheus metrics exporter")?;
    }

    Ok(())
}

pub fn shutdown() {
    if let Some(provider) = TRACER_PROVIDER.get() {
        let _ = provider.shutdown();
    }
}
