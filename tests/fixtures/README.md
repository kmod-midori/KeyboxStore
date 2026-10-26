# Public test fixture

`keybox.xml` is the public testing keybox from
https://github.com/qwq233/OhMyKeymint/blob/master/template/keybox.xml,
retrieved on 2026-10-26 and included with the user's authorization.
It contains public test private keys, not production credentials.

The original file is unmodified. Its declared NumberOfKeyboxes is 2 despite
containing only one Keybox element. Tests cover accepting this stale count,
extracting leaf metadata from both chains, and exporting with the correct count.
