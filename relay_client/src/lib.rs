use {
    crate::error::{ClientError, RequestBuildError},
    ::http::{HeaderMap, Uri},
    relay_rpc::{
        auth::{SerializedAuthToken, RELAY_WEBSOCKET_ADDRESS},
        domain::{MessageId, ProjectId, SubscriptionId},
        rpc::{SubscriptionError, SubscriptionResult},
        user_agent::UserAgent,
    },
    serde::Serialize,
    std::sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    url::Url
};

pub mod error;
pub mod http;
pub mod websocket;

pub type HttpRequest<T> = ::http::Request<T>;

/// Relay authorization method. A wrapper around [`SerializedAuthToken`].
#[derive(Debug, Clone)]
pub enum Authorization {
    /// Uses query string to pass the auth token, e.g. `?auth=<token>`.
    Query(SerializedAuthToken),

    /// Uses the `Authorization: Bearer <token>` HTTP header.
    Header(SerializedAuthToken),
}

/// Relay connection options.
#[derive(Debug, Clone)]
pub struct ConnectionOptions {
    /// The Relay websocket address. The default address is
    /// `wss://relay.walletconnect.com`.
    pub address: String,

    /// The project-specific secret key. Can be generated in the Cloud Dashboard
    /// at the following URL: <https://cloud.walletconnect.com/app>
    pub project_id: ProjectId,

    /// The authorization method and auth token to use.
    pub auth: Authorization,

    /// Optional origin of the request. Subject to allow-list validation.
    pub origin: Option<String>,

    /// Optional user agent parameters.
    pub user_agent: Option<UserAgent>,
}

impl ConnectionOptions {
    pub fn new(project_id: impl Into<ProjectId>, auth: SerializedAuthToken) -> Self {
        Self {
            address: RELAY_WEBSOCKET_ADDRESS.into(),
            project_id: project_id.into(),
            auth: Authorization::Query(auth),
            origin: None,
            user_agent: None,
        }
    }

    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = address.into();
        self
    }

    pub fn with_origin(mut self, origin: impl Into<Option<String>>) -> Self {
        self.origin = origin.into();
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<Option<UserAgent>>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    pub fn as_url(&self) -> Result<Url, RequestBuildError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct QueryParams<'a> {
            project_id: &'a ProjectId,
            auth: Option<&'a SerializedAuthToken>,
            ua: Option<&'a UserAgent>,
        }

        let query = serde_qs::to_string(&QueryParams {
            project_id: &self.project_id,
            auth: if let Authorization::Query(auth) = &self.auth {
                Some(auth)
            } else {
                None
            },
            ua: self.user_agent.as_ref(),
        })
        .map_err(RequestBuildError::Query)?;

        let mut url = Url::parse(&self.address).map_err(|err|RequestBuildError::Url(err.to_string()))?;
        url.set_query(Some(&query));

        Ok(url)
    }

    fn as_ws_request(&self) -> Result<HttpRequest<()>, RequestBuildError> {
        use crate::websocket::WebsocketClientError;

        let url = self.as_url()?;

        let mut request =
            into_client_request(url.as_str()).map_err(|err|WebsocketClientError::IntoClientError(err.to_string()))?;

        self.update_request_headers(request.headers_mut())?;

        Ok(request)
    }

    fn update_request_headers(&self, headers: &mut HeaderMap) -> Result<(), RequestBuildError> {
        if let Authorization::Header(token) = &self.auth {
            let value = format!("Bearer {token}")
                .parse()
                .map_err(|_| RequestBuildError::Headers)?;

            headers.append("Authorization", value);
        }

        if let Some(origin) = &self.origin {
            let value = origin.parse().map_err(|_| RequestBuildError::Headers)?;

            headers.append("Origin", value);
        }

        Ok(())
    }
}

/// Generates unique message IDs for use in RPC requests. Uses 56 bits for the
/// timestamp with millisecond precision, with the last 8 bits from a monotonic
/// counter. Capable of producing up to `256000` unique values per second.
#[derive(Debug, Clone)]
pub struct MessageIdGenerator {
    next: Arc<AtomicU8>,
}

impl MessageIdGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates a [`MessageId`].
    pub fn next(&self) -> MessageId {
        let next = self.next.fetch_add(1, Ordering::Relaxed) as u64;
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let id = timestamp << 8 | next;

        MessageId::new(id)
    }
}

impl Default for MessageIdGenerator {
    fn default() -> Self {
        Self {
            next: Arc::new(AtomicU8::new(0)),
        }
    }
}

#[inline]
fn convert_subscription_result(
    res: SubscriptionResult,
) -> Result<SubscriptionId, error::Error<SubscriptionError>> {
    match res {
        SubscriptionResult::Id(id) => Ok(id),
        SubscriptionResult::Error(err) => Err(ClientError::from(err).into()),
    }
}

/// Generate a random key for the `Sec-WebSocket-Key` header.
pub fn generate_websocket_key() -> String {
    // a base64-encoded (see Section 4 of [RFC4648]) value that,
    // when decoded, is 16 bytes in length (RFC 6455)
    let r: [u8; 16] = rand::random();
    data_encoding::BASE64.encode(&r)
}

/// Converts a URL string into an HTTP request for initiating a WebSocket connection.
fn into_client_request(url: &str) -> Result<HttpRequest<()>, RequestBuildError> {
    let uri: Uri = url
        .parse()
        .map_err(|_| RequestBuildError::Url("Invalid url".to_owned()))?;
    let authority = uri
        .authority()
        .ok_or(RequestBuildError::Url("Url has not authority".to_owned()))?
        .as_str();
    let host = authority
        .find('@')
        .map(|idx| authority.split_at(idx + 1).1)
        .unwrap_or_else(|| authority);

    // Check if the host is empty (excluding the port)
    if host.split(':').next().unwrap_or("").is_empty() {
        return Err(RequestBuildError::Url("EmptyHostName".to_owned()));
    }

    let req = HttpRequest::builder()
        .method("GET")
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_websocket_key())
        .uri(uri)
        .body(())
        .map_err(|err| RequestBuildError::Url(err.to_string()))?;
    Ok(req)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{collections::HashSet, hash::Hash},
    };

    fn elements_unique<T>(iter: T) -> bool
    where
        T: IntoIterator,
        T::Item: Eq + Hash,
    {
        let mut set = HashSet::new();
        iter.into_iter().all(move |x| set.insert(x))
    }

    #[test]
    fn unique_message_ids() {
        let gen = MessageIdGenerator::new();
        // N.B. We can produce up to 256 unique values within 1ms.
        let values = (0..256).map(move |_| gen.next()).collect::<Vec<_>>();
        assert!(elements_unique(values));
    }
}
