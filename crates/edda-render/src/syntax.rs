//! Syntax-highlighted HTML for a source file, chosen by filename extension.
//!
//! Output is class-based (`<span class="...">`), not inline-styled — see
//! `highlight`'s doc comment — so a color theme lives entirely in CSS and
//! can be swapped without re-rendering anything. This never touches
//! `ammonia`: the HTML this module emits is built exclusively from
//! `syntect`'s own escaping of the source text (`syntect` HTML-escapes
//! every token span itself — confirmed by the
//! `escapes_html_special_characters_in_source` test below, not assumed),
//! never from caller-supplied HTML, so there is nothing here for a
//! sanitizer to catch that `syntect`'s escaping hasn't already handled.

use std::sync::OnceLock;

use syntect::html::{ClassStyle, ClassedHTMLGenerator};
use syntect::parsing::{SyntaxReference, SyntaxSet};
use syntect::util::LinesWithEndings;

fn syntax_set() -> &'static SyntaxSet {
    static SET: OnceLock<SyntaxSet> = OnceLock::new();
    // `_newlines`: required by `parse_html_for_line_which_includes_newline`
    // below (its own doc comment states this pairing explicitly) — the
    // `_nonewlines` variant is for the deprecated line-at-a-time API this
    // module doesn't use.
    SET.get_or_init(SyntaxSet::load_defaults_newlines)
}

/// Extension-only lookup — no `find_syntax_for_file` (that reads the file
/// from disk to sniff a shebang/modeline, which this module has no file
/// handle for; callers only ever have in-memory content plus a filename) and
/// no first-line sniffing, so a recognized extension with unusual content
/// still highlights as that language, and an unrecognized extension always
/// falls back to plain text rather than guessing.
fn syntax_for<'a>(syntax_set: &'a SyntaxSet, filename_hint: &str) -> &'a SyntaxReference {
    let extension = std::path::Path::new(filename_hint)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");
    syntax_set
        .find_syntax_by_extension(extension)
        .unwrap_or_else(|| syntax_set.find_syntax_plain_text())
}

/// Renders `source` as a syntax-highlighted `<pre><code>...</code></pre>`
/// fragment, choosing the language by `filename_hint`'s extension and
/// falling back to plain-text highlighting (still valid, just
/// syntax-free, HTML — never a panic or an error) for an unrecognized one.
///
/// Class-based rather than inline-styled: `ClassStyle::Spaced` emits
/// `<span class="source rust">`-shaped markup instead of baking a theme's
/// colors into `style="..."` on every span, so the color theme is a CSS
/// concern the frontend controls, not something re-rendered per request.
pub fn highlight(source: &str, filename_hint: &str) -> String {
    let syntax_set = syntax_set();
    let syntax = syntax_for(syntax_set, filename_hint);

    let mut generator =
        ClassedHTMLGenerator::new_with_class_style(syntax, syntax_set, ClassStyle::Spaced);
    for line in LinesWithEndings::from(source) {
        // Only errors on a `syntect` internal invariant violation (a
        // malformed bundled syntax definition), never on the *content*
        // being highlighted — arbitrary source text, including invalid
        // UTF-8-adjacent or empty input, is always valid input here.
        generator
            .parse_html_for_line_which_includes_newline(line)
            .expect("syntect's bundled default syntaxes are well-formed");
    }
    let body = generator.finalize();

    format!("<pre class=\"edda-highlight\"><code>{body}</code></pre>")
}

#[cfg(test)]
mod tests {
    use super::highlight;

    /// Confirms `syntect` itself HTML-escapes source text (this module
    /// relies on that instead of separately escaping) rather than assuming
    /// it — a `<` in Rust source (a generic bracket, extremely common)
    /// must come out as `&lt;` in the token span, not literal `<`.
    #[test]
    fn escapes_html_special_characters_in_source() {
        let html = highlight("let v: Vec<u8> = Vec::new();\n", "main.rs");
        // `syntect` wraps sub-tokens in their own `<span>`s, so the escaped
        // angle brackets aren't textually adjacent to "u8" in the output —
        // what matters is that a literal, unescaped `<u8>` never appears
        // (that would be a real HTML tag), and that `&lt;`/`&gt;` do appear
        // somewhere as the escaped stand-ins for it.
        assert!(!html.contains("<u8>"), "unescaped angle bracket: {html}");
        assert!(html.contains("&lt;"), "missing `<` escape: {html}");
        assert!(html.contains("&gt;"), "missing `>` escape: {html}");
    }

    #[test]
    fn highlights_rust_with_recognizable_token_spans() {
        let html = highlight("fn main() {\n    let x = 1;\n}\n", "main.rs");
        assert!(html.starts_with("<pre class=\"edda-highlight\"><code>"));
        assert!(
            html.contains("<span class="),
            "no token spans at all: {html}"
        );
        // `fn`/`let` are keywords in every Rust TextMate grammar variant —
        // this asserts real language-aware tokenization happened, not just
        // "some span exists somewhere."
        assert!(
            html.contains("keyword") || html.contains("storage"),
            "no keyword-class span for `fn`/`let`: {html}"
        );
    }

    #[test]
    fn highlights_toml_with_recognizable_token_spans() {
        let html = highlight(
            "[package]\nname = \"edda\"\nversion = \"0.1.0\"\n",
            "Cargo.toml",
        );
        assert!(html.contains("<span class="), "no token spans: {html}");
        assert!(html.contains("edda"), "content missing: {html}");
    }

    #[test]
    fn highlights_sql_with_recognizable_token_spans() {
        let html = highlight("SELECT id, name FROM users WHERE id = 1;\n", "query.sql");
        assert!(html.contains("<span class="), "no token spans: {html}");
        assert!(
            html.to_lowercase().contains("keyword") || html.contains("select"),
            "no keyword-shaped span for SELECT: {html}"
        );
    }

    #[test]
    fn highlights_html_and_css_with_recognizable_token_spans() {
        let html_fragment = highlight("<div class=\"a\">hi</div>\n", "index.html");
        assert!(
            html_fragment.contains("<span class="),
            "html: no spans: {html_fragment}"
        );

        let css = highlight("body {\n  color: red;\n}\n", "style.css");
        assert!(css.contains("<span class="), "css: no spans: {css}");
    }

    #[test]
    fn highlights_markdown_with_recognizable_token_spans() {
        let html = highlight("# Heading\n\nSome *text*.\n", "README.md");
        assert!(html.contains("<span class="), "markdown: no spans: {html}");
    }

    #[test]
    fn falls_back_to_plain_text_for_an_unrecognized_extension_without_panicking() {
        let html = highlight("just some\ntext content\n", "notes.thisisnotarealextension");
        assert!(html.contains("just some"));
        assert!(html.contains("text content"));
    }
}
