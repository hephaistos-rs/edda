//! GitHub-Flavored-Markdown-to-HTML rendering, unconditionally sanitized.
//!
//! `render` is this module's *only* public entry point. There is
//! deliberately no lower-level "just run `comrak`, skip sanitization"
//! function exported alongside it — every markdown render in this codebase
//! must be XSS-safe, and the only way to guarantee that is to make the
//! unsafe half of the pipeline unreachable from outside this module, not to
//! trust every call site to remember the second step.

/// GFM extensions enabled: tables, task lists, strikethrough, and autolinks
/// — the four surface features a README or PR-body-shaped markdown string
/// commonly relies on. `render.r#unsafe = true` is required for `comrak` to
/// emit the task-list extension's raw `<input type="checkbox">` markup at
/// all (otherwise it's dropped at the parser stage, before sanitization
/// ever runs) — enabling it does not weaken this function's safety
/// guarantee, because every byte of `comrak`'s output, unsafe-rendering or
/// not, is piped through `ammonia::clean` below before this function
/// returns anything.
fn comrak_options() -> comrak::Options<'static> {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.tasklist = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.render.r#unsafe = true;
    options
}

/// `ammonia`'s default tag allowlist has no entry for `<input>` at all (it
/// predates HTML forms being relevant to "sanitize some prose"), which
/// would otherwise strip every task-list checkbox `comrak` emits. Extending
/// the allowlist to permit exactly `<input type="" checked="" disabled="">`
/// is still full sanitization — every other tag/attribute this builder
/// doesn't explicitly know about is stripped exactly as ammonia's own
/// defaults would strip it, including `<script>`, event-handler attributes
/// (`onerror`, `onclick`, ...), and `javascript:`-scheme links. Built fresh
/// per call rather than cached: `ammonia::Builder` is cheap to construct
/// and this keeps the function free of shared mutable state.
fn sanitize(html: &str) -> String {
    ammonia::Builder::default()
        .add_tags(["input"])
        .add_tag_attributes("input", ["type", "checked", "disabled"])
        .clean(html)
        .to_string()
}

/// Renders `input` (GitHub-Flavored Markdown) to sanitized HTML. This is
/// the only markdown-rendering path in the workspace — nothing should call
/// `comrak::markdown_to_html` directly, anywhere, ever; every markdown
/// string that reaches a browser must go through this function so
/// sanitization is structurally guaranteed rather than a convention callers
/// have to remember.
pub fn render(input: &str) -> String {
    let html = comrak::markdown_to_html(input, &comrak_options());
    sanitize(&html)
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn renders_gfm_tables_task_lists_and_strikethrough() {
        let input = "\
| a | b |
|---|---|
| 1 | 2 |

- [x] done
- [ ] not done

~~struck~~
";
        let html = render(input);
        assert!(html.contains("<table"), "table: {html}");
        assert!(html.contains("<th>a</th>"), "table header: {html}");
        assert!(
            html.contains(r#"type="checkbox""#) && html.contains("checked"),
            "checked task: {html}"
        );
        assert!(html.contains("<del>struck</del>"), "strikethrough: {html}");
    }

    #[test]
    fn renders_autolinks() {
        let html = render("See www.example.com for details.\n");
        assert!(html.contains("<a "), "autolink: {html}");
        assert!(html.contains("example.com"), "autolink target: {html}");
    }

    /// The XSS regression test: `<script>` must never survive, and neither
    /// should an `onerror`-smuggled-through-`<img>` payload — a classic
    /// "the tag itself looks legitimate" vector that a naive "strip
    /// `<script>` tags" filter would miss but a real allowlist-based
    /// sanitizer (what `ammonia` is) catches by only ever permitting
    /// attributes it explicitly knows are safe.
    #[test]
    fn strips_script_tags_and_event_handler_attributes() {
        let input = "\
Hello <script>alert(1)</script> world.

<img src=\"x\" onerror=\"alert(2)\">

[link](javascript:alert(3))
";
        let html = render(input);
        assert!(!html.contains("<script"), "script tag survived: {html}");
        assert!(
            !html.contains("alert(1)"),
            "script payload survived: {html}"
        );
        assert!(!html.contains("onerror"), "event handler survived: {html}");
        assert!(
            !html.contains("alert(2)"),
            "onerror payload survived: {html}"
        );
        assert!(
            !html.contains("javascript:"),
            "javascript: URI survived: {html}"
        );
    }

    #[test]
    fn strips_disallowed_tags_while_keeping_safe_content() {
        let html = render("<style>body{display:none}</style>\n\nSome *text*.\n");
        assert!(!html.contains("<style"), "style tag survived: {html}");
        assert!(html.contains("<em>text</em>"), "safe markdown lost: {html}");
    }
}
