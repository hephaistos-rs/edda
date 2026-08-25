//! Presentation-layer rendering: markdown-to-HTML and syntax-highlighted
//! code. Pure, in-memory, no I/O — every syntax/theme definition `syntax`
//! uses is compiled into the binary via `syntect`'s bundled defaults, and
//! `markdown::render` never touches the filesystem or network.
//!
//! Kept as its own crate rather than folded into `edda-domain`: these three
//! dependencies (`comrak`, `ammonia`, `syntect`) are real weight for a
//! presentation concern, and `edda-domain` is meant to stay a small, pure
//! functional core that every other crate can depend on cheaply. Nothing
//! here encodes a business rule or an entity invariant — it only turns text
//! that already exists into HTML — so it doesn't belong in the domain
//! crate, and any crate rendering content (today: `edda-web`'s server
//! functions) can depend on this one directly instead.

pub mod markdown;
pub mod syntax;
