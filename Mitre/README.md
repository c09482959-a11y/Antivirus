UMIGE Enterprise ATT&CK configuration

MITRE/ATT&CK is enabled by canonical typed application defaults during normal startup.
Mitre/mitre_config.toml is an editable explicit override and is not read unless --mitre-config is supplied.
Mitre/mitre_defaults.toml is a generated human-readable projection only and is never a runtime configuration source.
The packaged Mitre/enterprise-attack.json seed is discovered independently through ResourceRootSnapshot.
allow_download is false by default. Per-file scans never access the network.
The GitHub Contents API sha is the trusted Git-blob identity for an explicitly authorized refresh.
Existing generated controls are never overwritten during ordinary startup.
