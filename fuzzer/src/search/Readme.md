# How to write a mutation strategy?
- see `det.rs` as an example: build it against a `&mut SearchHandler`, take the seed's
  `&[TaintHint]` as read-only guidance, and mutate `handler.buf` clones + `handler.execute()`.
  Success is judged by the executor's own new-coverage detection, not by anything the
  operator itself tracks.
