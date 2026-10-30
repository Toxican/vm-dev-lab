# Changelog

All notable public changes are documented in this file. The format follows
Keep a Changelog, and versions follow Semantic Versioning where appropriate for
the project's early development stage.

## 0.5.0 – Initial Public Release (2026-10-30)

### Security

- Unrelated or incompletely bound libvirt resources are neither adopted nor
  changed.
- Host changes require a reviewed plan and confirmation token.
- Private runtime state, keys, images, and VM disks are separated from the
  repository.

### License

- Project-owned code is released under the MIT License.
- Python dependencies and external system tools retain their respective
  licenses and are not copied into the project wheel.

### Known limitations

- Early development; no stable API or cross-release upgrade guarantee.
- Automated Host Setup supports only Arch Linux x86_64.
- Host Setup is **Heavy Development / Experimental** and has only offline
  fixture coverage.
- A complete fresh-host installation has not been independently validated.
- No GUI, USB assignment, audio integration, or general ISO installation.
