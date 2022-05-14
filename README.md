# Firefox Symbols Upload

Uploads crashreport symbols created through Mozilla's Mach buildsystem
to symbols.mozilla.org.

This tool scrapes the channel for the `symbols` output provided by
packages created through `buildMozillaMach` and uploads the zip file
contained within to Mozilla, so it can be used in their crash reporting
platform at https://crash-stats.mozilla.org.

## Note

Only useful for the maintainer of `buildMozillaMach` in nixpkgs
and requires an account with upload permissions on
https://symbols.mozilla.org.

