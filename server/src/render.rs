use actix_web::{HttpResponse, web};
use handlebars::Handlebars;
use log::error;
use serde::Serialize;

use crate::dane_result::DaneResult;

use crate::config::{STATIC_CONTENT_CONFIG, StaticContentConfig};

#[derive(Serialize)]
struct RenderData<'a, T> {
    config: StaticContentConfig,
    data: &'a T,
}

pub fn render(
    hb: web::Data<Handlebars<'_>>,
    page_path: &str,
    data: &Option<DaneResult>,
) -> HttpResponse {
    let render_data = RenderData {
        config: STATIC_CONTENT_CONFIG.clone(),
        data,
    };

    match hb.render(page_path, &render_data) {
        Ok(body) => HttpResponse::Ok().body(body),
        Err(err) => {
            error!("Template rendering error: {err}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use handlebars::DirectorySourceOptions;

    async fn render_index(result: DaneResult) -> String {
        let mut handlebars = Handlebars::new();
        handlebars
            .register_templates_directory("./static/", DirectorySourceOptions::default())
            .unwrap();
        let response = render(web::Data::new(handlebars), "index", &Some(result));
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[actix_web::test]
    async fn test_render_multiple_keys() {
        let dane_fetch = dane::fetch::DaneFetch {
            data: vec![
                std::fs::read("../test_files/test_key").unwrap(),
                std::fs::read("../test_files/test_expired_key").unwrap(),
            ],
            errors: vec![],
            successes: vec![],
            timestamp: Utc::now(),
        };
        let result = DaneResult::from(dane_fetch, "user_id".to_string(), "dns_name".to_string());
        let body = render_index(result).await;
        assert!(body.contains("AC48BC1F029B6188D97E2D807C855DB4466DF0C6"));
        assert!(body.contains("A03351F7677A6D0B94F224A636CB3789EAC25E50"));
        assert!(body.contains(r#"<div class="v keys-count">2</div>"#));
    }

    #[actix_web::test]
    async fn test_render_no_keys() {
        let dane_fetch = dane::fetch::DaneFetch {
            data: vec![],
            errors: vec![],
            successes: vec![],
            timestamp: Utc::now(),
        };
        let result = DaneResult::from(dane_fetch, "user_id".to_string(), "dns_name".to_string());
        let body = render_index(result).await;
        assert!(body.contains("No keys found"));
    }
}
