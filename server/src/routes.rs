#[cfg(feature = "dane-cache")]
use crate::WebCache;

use crate::dane_result;
use crate::render;
use actix_web::error::ErrorBadRequest;
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use actix_web::{HttpResponse, Responder, Result, get, web};
use handlebars::Handlebars;
use render::render;
use serde::Deserialize;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(api),
    components(schemas(
        dane_result::DaneResult,
        dane_result::DaneError,
        dane_result::DaneKey,
        dane_result::DaneSuccess
    )),
    info(
        title = "DANE Tester API",
        version = "0.1.0",
        description = "API for testing OpenPGP DANE (RFC 7929) OPENPGPKEY DNS record lookups",
        contact(name = "Alexis Lowe", url = "https://chimbosonic.com"),
        license(
            name = "MIT",
            url = "https://github.com/chimbosonic/dane-tester/blob/master/LICENSE"
        )
    )
)]
pub struct ApiDoc;

#[derive(Deserialize, utoipa::IntoParams, Debug)]
struct FormData {
    /// Email address to lookup OPENPGPKEY DNS record for
    email: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/lookup",
    params(FormData),
    responses(
        (status = 200, description = "DANE lookup successful", body = dane_result::DaneResult),
        (status = 400, description = "Missing email parameter")
    ),
    tag = "DANE Lookup"
)]
#[get("/api/lookup")]
#[cfg_attr(feature = "otel", tracing::instrument)]
pub async fn api(
    form: web::Query<FormData>,
    dns_server: web::Data<Option<String>>,
    #[cfg(feature = "dane-cache")] cache: web::Data<WebCache>,
) -> Result<impl Responder> {
    let email = match &form.email {
        Some(email) => email,
        None => {
            return Err(ErrorBadRequest("Missing email parameter"));
        }
    };

    #[cfg(feature = "dane-cache")]
    let (result, cache_set_future) =
        dane_result::get_dane_cached(email, &cache, dns_server.as_deref()).await;

    #[cfg(not(feature = "dane-cache"))]
    let result = dane_result::get_dane(email, dns_server.as_deref()).await;

    let result = web::Json(result)
        .customize()
        .insert_header((CACHE_CONTROL, "no-store"));

    #[cfg(feature = "dane-cache")]
    dane_result::unwrap_cache_future(cache_set_future).await;

    Ok(result)
}

#[get("/")]
#[cfg_attr(feature = "otel", tracing::instrument)]
pub async fn lookup(
    form: web::Query<FormData>,
    hb: web::Data<Handlebars<'_>>,
    dns_server: web::Data<Option<String>>,
    #[cfg(feature = "dane-cache")] cache: web::Data<WebCache>,
) -> HttpResponse {
    let email = match &form.email {
        Some(email) => email,
        None => {
            let mut response = render(hb, "index", &None);
            response.headers_mut().insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=604800"),
            );
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
            return response;
        }
    };

    #[cfg(feature = "dane-cache")]
    let (result, cache_set_future) =
        dane_result::get_dane_cached(email, &cache, dns_server.as_deref()).await;

    #[cfg(not(feature = "dane-cache"))]
    let result = dane_result::get_dane(email, dns_server.as_deref()).await;

    let mut response = render(hb, "index", &Some(result));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));

    #[cfg(feature = "dane-cache")]
    dane_result::unwrap_cache_future(cache_set_future).await;

    response
}

#[get("/.well-known/sitemap.xml")]
#[cfg_attr(feature = "otel", tracing::instrument)]
pub async fn serve_sitemap(hb: web::Data<Handlebars<'_>>) -> HttpResponse {
    let mut response = render(hb, "sitemap", &None);
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=604800"),
    );
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
    response
}
