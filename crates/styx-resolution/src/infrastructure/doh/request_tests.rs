use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::*;

const MESSAGE: &[u8] = &[0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];

fn resource() -> DohResourcePath {
    DohResourcePath::new("/dns-query".into()).unwrap()
}

fn cap(octets: usize) -> StreamMessageLimit {
    StreamMessageLimit::from_configured(octets).unwrap()
}

fn get(query: Option<&str>) -> DohHead<'_> {
    DohHead {
        method: "GET",
        path: "/dns-query",
        query,
        content_type: None,
        content_length: None,
    }
}

fn post<'a>(content_type: Option<&'a str>, content_length: Option<&'a str>) -> DohHead<'a> {
    DohHead {
        method: "POST",
        path: "/dns-query",
        query: None,
        content_type,
        content_length,
    }
}

#[test]
fn get_decodes_the_unpadded_base64url_dns_parameter() {
    let encoded = URL_SAFE_NO_PAD.encode(MESSAGE);
    let query = format!("ct=x&dns={encoded}");
    assert_eq!(
        extract_head(&get(Some(&query)), &resource(), cap(512)),
        Ok(DohRequestForm::GetQueryParameter(MESSAGE.to_vec()))
    );
}

#[test]
fn get_without_a_usable_parameter_is_a_client_error() {
    for query in [None, Some(""), Some("dns="), Some("other=1")] {
        assert_eq!(
            extract_head(&get(query), &resource(), cap(512)),
            Err(DohError::MissingDnsParameter),
            "{query:?}"
        );
    }
    for bad in ["dns=***", "dns=AAAA====", "dns=A"] {
        assert_eq!(
            extract_head(&get(Some(bad)), &resource(), cap(512)),
            Err(DohError::MalformedBase64Url),
            "{bad}"
        );
    }
}

#[test]
fn an_oversized_get_parameter_is_refused_before_decoding() {
    let huge = format!("dns={}", "A".repeat(1_000_000));
    assert_eq!(
        extract_head(&get(Some(&huge)), &resource(), cap(512)),
        Err(DohError::BodyTooLarge)
    );
    let just_over = format!("dns={}", URL_SAFE_NO_PAD.encode([0u8; 513]));
    assert_eq!(
        extract_head(&get(Some(&just_over)), &resource(), cap(512)),
        Err(DohError::BodyTooLarge)
    );
}

#[test]
fn post_needs_the_dns_media_type_and_a_declared_length_under_the_cap() {
    assert_eq!(
        extract_head(
            &post(Some("Application/DNS-Message; q=1"), Some("17")),
            &resource(),
            cap(512)
        ),
        Ok(DohRequestForm::PostBody)
    );
    assert_eq!(
        extract_head(&post(Some("text/plain"), None), &resource(), cap(512)),
        Err(DohError::UnsupportedMediaType)
    );
    assert_eq!(
        extract_head(&post(None, None), &resource(), cap(512)),
        Err(DohError::UnsupportedMediaType)
    );
    assert_eq!(
        extract_head(
            &post(Some(DNS_MESSAGE_MEDIA_TYPE), Some("18446744073709551615")),
            &resource(),
            cap(512)
        ),
        Err(DohError::BodyTooLarge)
    );
    assert_eq!(
        extract_head(
            &post(Some(DNS_MESSAGE_MEDIA_TYPE), Some("0")),
            &resource(),
            cap(512)
        ),
        Err(DohError::EmptyBody)
    );
}

#[test]
fn other_paths_and_methods_are_refused_path_first() {
    let mut head = get(Some("dns=AAAA"));
    head.path = "/other";
    assert_eq!(
        extract_head(&head, &resource(), cap(512)),
        Err(DohError::PathNotFound)
    );
    head.path = "/dns-query";
    head.method = "PUT";
    assert_eq!(
        extract_head(&head, &resource(), cap(512)),
        Err(DohError::MethodNotAllowed)
    );
}

#[test]
fn bodies_are_judged_against_the_cap() {
    assert_eq!(accept_body(&[], cap(512)), Err(DohError::EmptyBody));
    assert_eq!(accept_body(&[0; 512], cap(512)), Ok(()));
    assert_eq!(
        accept_body(&[0; 513], cap(512)),
        Err(DohError::BodyTooLarge)
    );
}

#[test]
fn every_error_maps_to_its_documented_status() {
    let statuses = [
        (DohError::MethodNotAllowed, 405),
        (DohError::PathNotFound, 404),
        (DohError::UnsupportedMediaType, 415),
        (DohError::MissingDnsParameter, 400),
        (DohError::MalformedBase64Url, 400),
        (DohError::BodyTooLarge, 413),
        (DohError::EmptyBody, 400),
        (DohError::Unanswerable, 400),
        (DohError::StreamBudgetExceeded, 503),
    ];
    for (error, status) in statuses {
        assert_eq!(error.status(), status, "{error}");
    }
}
