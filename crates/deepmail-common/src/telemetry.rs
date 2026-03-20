//! Shared tracing + OpenTelemetry initialization for all DeepMail binaries.

use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{LoggingConfig, ObservabilityConfig};

/// Initialize the tracing subscriber with optional OTLP export.
pub fn init_tracing(
    logging: &LoggingConfig,
    observability: &ObservabilityConfig,
    service_name: &str,
) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&logging.level));

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let provider = if observability.otlp_enabled {
        build_otlp_provider(observability, service_name)
    } else {
        opentelemetry_sdk::trace::SdkTracerProvider::builder().build()
    };

    let tracer = provider.tracer(service_name.to_string());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    match logging.format.as_str() {
        "json" => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }
}

fn build_otlp_provider(
    config: &ObservabilityConfig,
    _service_name: &str,
) -> opentelemetry_sdk::trace::SdkTracerProvider {
    use opentelemetry_otlp::SpanExporter;

    let exporter = match SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()
    {
        Ok(exp) => exp,
        Err(e) => {
            eprintln!(
                "WARNING: Failed to build OTLP exporter ({}), traces will not be exported: {}",
                config.otlp_endpoint, e
            );
            return opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        }
    };

    let batch_processor = opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter)
        .with_max_export_batch_size(config.otlp_batch_size as usize)
        .with_scheduled_delay(std::time::Duration::from_secs(
            config.otlp_batch_timeout_secs,
        ))
        .build();

    opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .build()
}
