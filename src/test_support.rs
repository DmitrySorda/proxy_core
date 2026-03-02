use crate::filter::HttpClientLike;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ResponseSpec {
    pub body: Result<Vec<u8>, String>,
    pub delay_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TestHttpClient {
    responses: HashMap<String, ResponseSpec>,
}

impl TestHttpClient {
    pub fn new(responses: HashMap<String, ResponseSpec>) -> Self {
        Self { responses }
    }

    pub fn boxed(responses: HashMap<String, ResponseSpec>) -> Arc<dyn HttpClientLike> {
        Arc::new(Self::new(responses)) as Arc<dyn HttpClientLike>
    }
}

impl HttpClientLike for TestHttpClient {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            let spec = self.responses.get(url).cloned().unwrap_or(ResponseSpec {
                body: Err("not_found".to_string()),
                delay_ms: 0,
            });
            if spec.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(spec.delay_ms)).await;
            }
            spec.body
        })
    }

    fn post<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move { Err("not_supported".to_string()) })
    }
}
