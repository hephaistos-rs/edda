//! Markdown rendering plus Edda-specific cross-reference auto-linking.
//!
//! `edda-render` deliberately depends on no other Edda crate (it is the
//! sanitized-markdown leaf), so the `#5` / `owner/repo#5` linkification —
//! which needs `edda_domain::crossref` and knowledge of Edda's URL shape —
//! lives here, as a pass over the already-rendered, already-sanitized HTML.
//! Every markdown string that reaches a browser still goes through
//! `edda_render::markdown::render` first, so the XSS guarantee is intact;
//! this only rewrites plain `#5`-shaped text runs into `<a>` links, and
//! never touches text inside an existing `<a>`, `<code>`, or `<pre>`.

use edda_domain::{parse_cross_reference_spans, CrossReference};

/// The repository a body belongs to — the target for a bare `#5`.
#[derive(Clone, Copy)]
pub struct RefContext<'a> {
    pub owner: &'a str,
    pub repo: &'a str,
}

/// Renders `markdown` to sanitized HTML, then auto-links cross-references.
pub fn body_html(markdown: &str, ctx: RefContext<'_>) -> String {
    linkify_cross_references(&edda_render::markdown::render(markdown), ctx)
}

/// The `href` a cross-reference points at. A bare `#5` resolves within
/// `ctx`; `owner/repo#5` names its own repository. Numbers route to
/// `/issues/{n}` — issues and pull requests share one per-repository
/// number space, and the issue route redirects to the PR when the number
/// is a PR.
fn href_for(cref: &CrossReference, ctx: RefContext<'_>) -> String {
    let (owner, repo) = match &cref.repository {
        Some((owner, repo)) => (owner.as_str(), repo.as_str()),
        None => (ctx.owner, ctx.repo),
    };
    format!("/{owner}/{repo}/issues/{}", cref.number)
}

/// `+1` for an opening `<a>`/`<code>`/`<pre>`, `-1` for its close, `0` for
/// anything else. Parses the tag name so `<abbr>` / `<article>` (both on
/// ammonia's allowlist) do not get mistaken for `<a>`.
fn skip_tag_effect(tag: &str) -> i32 {
    let inner = tag
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim_end_matches('/')
        .trim();
    let (closing, rest) = match inner.strip_prefix('/') {
        Some(rest) => (true, rest.trim()),
        None => (false, inner),
    };
    let name = rest
        .split(|c: char| c.is_whitespace())
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match name.as_str() {
        "a" | "code" | "pre" => {
            if closing {
                -1
            } else {
                1
            }
        }
        _ => 0,
    }
}

/// Rewrites `#5` / `owner/repo#5` runs in `html`'s text nodes into links.
/// A hand-rolled single pass rather than a DOM library: the input is the
/// small, already-sanitized output of `comrak` + `ammonia`, and all we
/// need is "am I inside a tag / inside `<a>`/`<code>`/`<pre>`".
fn linkify_cross_references(html: &str, ctx: RefContext<'_>) -> String {
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len() + 32);
    let mut i = 0;
    let mut skip_depth: i32 = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let Some(rel_end) = html[i..].find('>') else {
                out.push_str(&html[i..]);
                break;
            };
            let tag = &html[i..=i + rel_end];
            skip_depth = (skip_depth + skip_tag_effect(tag)).max(0);
            out.push_str(tag);
            i += rel_end + 1;
            continue;
        }
        let text_end = html[i..].find('<').map_or(html.len(), |rel| i + rel);
        let text = &html[i..text_end];
        if skip_depth == 0 {
            out.push_str(&linkify_text_run(text, ctx));
        } else {
            out.push_str(text);
        }
        i = text_end;
    }
    out
}

fn linkify_text_run(text: &str, ctx: RefContext<'_>) -> String {
    let spans = parse_cross_reference_spans(text);
    if spans.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + spans.len() * 32);
    let mut cursor = 0;
    for (range, cref) in spans {
        out.push_str(&text[cursor..range.start]);
        let token = &text[range.clone()];
        // `token` is `#5` / `owner/repo#5` — digits plus the repo-name
        // charset, `/` and `#`; HTML-safe as text, and `href_for` builds a
        // path from the same safe pieces, so no escaping is needed.
        out.push_str(&format!("<a href=\"{}\">{token}</a>", href_for(&cref, ctx)));
        cursor = range.end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RefContext<'static> {
        RefContext {
            owner: "octo",
            repo: "core",
        }
    }

    #[test]
    fn bare_and_qualified_refs_become_links() {
        let html = body_html("See #12 and other/repo#3.", ctx());
        assert!(
            html.contains(r#"<a href="/octo/core/issues/12">#12</a>"#),
            "{html}"
        );
        assert!(
            html.contains(r#"<a href="/other/repo/issues/3">other/repo#3</a>"#),
            "{html}"
        );
    }

    #[test]
    fn refs_inside_code_and_existing_links_are_left_alone() {
        let html = body_html("`#12` stays code and [#5](/x) stays a link", ctx());
        assert!(html.contains("<code>#12</code>"), "{html}");
        assert!(
            !html.contains(r#"<a href="/octo/core/issues/5">"#),
            "{html}"
        );
    }

    #[test]
    fn an_abbr_element_is_not_treated_as_an_anchor() {
        let html = linkify_cross_references("<abbr>see #7</abbr>", ctx());
        assert!(
            html.contains(r#"<a href="/octo/core/issues/7">#7</a>"#),
            "{html}"
        );
    }

    #[test]
    fn plain_prose_without_refs_is_unchanged_apart_from_markdown() {
        let html = body_html("just some text", ctx());
        assert_eq!(html.trim(), "<p>just some text</p>");
    }
}
