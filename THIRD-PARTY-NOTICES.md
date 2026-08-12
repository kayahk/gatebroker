# Third-party notices

GateBroker is distributed under Apache-2.0. It depends on the third-party packages
below, and its self-contained CLI archives and container image embed them. All are
under permissive licenses compatible with Apache-2.0 redistribution.

Regenerate this list when dependencies change:

```shell
uv run python - <<'PY'
from importlib.metadata import distributions
for dist in sorted(distributions(), key=lambda d: d.metadata["Name"].lower()):
    meta = dist.metadata
    license_name = meta.get("License-Expression") or meta.get("License") or next(
        (c.rsplit("::", 1)[-1].strip() for c in meta.get_all("Classifier") or []
         if c.startswith("License ::")), "see package metadata")
    print(f"{meta['Name']} {dist.version} — {license_name}")
PY
```

## Direct dependencies

| Package | License |
| --- | --- |
| click | BSD-3-Clause |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| fastapi | MIT |
| httpx | BSD-3-Clause |
| keyring | MIT |
| msal | MIT |
| PyJWT | MIT |
| uvicorn | BSD-3-Clause |

## Transitive dependencies

Their transitive closure adds packages under MIT, BSD-2-Clause, BSD-3-Clause,
Apache-2.0, MIT-0, and the Python Software Foundation License, plus the two noted
below.

## Notes that need attention when redistributing

**`certifi` is MPL-2.0.** Mozilla Public License 2.0 is file-level weak copyleft.
Redistributing it inside a bundled archive or container image is permitted, and the
obligation is to make the source of the MPL-covered files available to recipients.
GateBroker ships `certifi` unmodified, so this notice and its upstream location
satisfy that: <https://github.com/certifi/python-certifi>.

**`pyinstaller` is GPL-2.0-or-later with a bootloader exception.** It is a
build-time dependency (the `bundle` extra) and is not a runtime dependency, but the
bootloader it embeds does ship inside the released executables. PyInstaller's
license grants an explicit exception permitting the bundled application to be
distributed under any license, so the Apache-2.0 GateBroker archives are compliant:
<https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt>.

## Interoperating services

GateBroker speaks the OpenAI and Anthropic HTTP API shapes and can front any
gateway that implements them. It vendors no code from OpenAI, Anthropic, LiteLLM,
or Microsoft, and is not affiliated with or endorsed by any of them. Those names
appear only to describe interoperability, and remain the trademarks of their
respective owners.
