UMIGE VirusTotal configuration

VirusTotal/virustotal_config.toml is generated when missing, schema-validated, and loaded automatically.
The generated and code-owned default is enabled = false. Disabled VirusTotal performs no connectivity probe or credential resolution.
When enabled = true, one bounded probe to the code-owned VirusTotal service target runs before credential/runtime-prerequisite validation.
An offline result is session-scoped network_unavailable and never rewrites the persisted enabled request.
The editable configuration stores only the environment-variable name used to obtain the API key; no connectivity bypass or endpoint override exists.
The API key itself is never written to configuration, logs, reports, manifests, tests, or packages.
Official VirusTotal API endpoints and probe target are owned by the canonical client and are not configurable.
Every VirusTotal state is external corroboration only and never changes local evidence, score, verdict, Tags, Chains, MITRE, or learning.
