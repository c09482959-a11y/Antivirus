UMIGE YARA configuration

Normal startup uses canonical typed YARA defaults and does not read Yara/yara_config.toml.
Yara/yara_config.toml is the editable input and is loaded only when --yara-config explicitly selects that canonical root file.
Full YARA automatic download remains disabled by default; YARA-light automatic download remains enabled.
Official archives require the exact release-wide YARA Forge SHA-256 manifest and local SHA-256 verification.
ETag and Last-Modified are freshness metadata only. Existing user configuration edits are never overwritten.
