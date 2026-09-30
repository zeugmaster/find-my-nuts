# Third-party notices and provenance

This proof of concept combines separately sourced material. License texts in
the tree govern their respective code; this notice does not replace them.

## Nucula wallet

The starting tree was the local `embedded/nucula` repository at revision
`85ac407659e271db0e95bb6293f406cbf54ab564`. The new project was cloned into
`find-my-nuts` and developed on `feat/find-my-nuts-ttgo`; the reference working
tree was not modified.

No project-level license file was present in that Nucula revision. The AGPL
text added at this repository's root therefore does not itself grant rights in
unmarked upstream Nucula files. Confirm the upstream author's terms before
redistributing a combined binary or source release.

## Find My transport and receiver

The transport/protocol/receiver work is derived from the local `esp-find-my`
reference at revision `c3b7ecef583457d08b31493d3972bac955427286`, which in
turn identifies `positive-security/send-my` and OpenHaystack as sources. The
adapted files carry `SPDX-License-Identifier: AGPL-3.0-only`; the complete GNU
Affero General Public License v3 text is in [LICENSE](LICENSE).

FindMy.py is installed separately from `receiver/requirements.txt` and retains
its own copyright, license, and service constraints.

## micro-ecc

The P-224 validity check vendors micro-ecc by Kenneth MacKay under the BSD
2-Clause license. Its text is retained at
`components/find_my_transport/third_party/micro-ecc/LICENSE`.

## blst

The Nucula BLS component vendors Supranational's blst under Apache License 2.0.
Its license is retained at `components/blst/blst/LICENSE`.

## secp256k1

`components/secp256k1/libsecp256k1` is a Git submodule of Bitcoin Core's
libsecp256k1 under the permissive license retained in that submodule's
`COPYING` file.
