# Definition scanner dependencies

The existing `golang.org/x/text` dependency is now direct for local NFKC and
case folding; its BSD licence remains in the module distribution. No runtime
network access is added.

`github.com/mtibben/confusables` is pinned to
`v0.0.0-20210201002637-9d1b0723b659`. Its local Skeleton function applies NFD,
the generated confusable mapping, then NFD; the generated table header dates its
Unicode data to 2020-02-13. It has no runtime fetching or extra transitive modules.
The BSD notice is preserved in [confusables.txt](confusables.txt). The generated
module table preserves Unicode's data attribution and terms link. Newer
confusables are a known coverage limitation. No third-party corpus text is
vendored, and the existing pinned public-corpus manifest is unchanged.
