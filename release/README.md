# Release procedure

Releases start with the manually dispatched `release.yml` workflow. It builds Windows amd64/arm64 and Linux amd64/arm64 binaries, checksums, SBOM material, and Linux OCI archives. Pinned scanners inspect full history and each immutable archive before any image publication.

The workflow creates a draft GitHub release only. A maintainer verifies the release checklist, scan metadata, checksums, provenance, and optional protected-environment interoperability and ACME staging evidence before publishing it.

Ordinary CI uses fake DNS, origins, and CA material. It never requires public inbound connectivity, a real ACME account, an Anthropic account, or repository secrets.
