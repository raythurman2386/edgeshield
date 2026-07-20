# Licensing

EdgeShield is licensed under the **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE)).

The Apache 2.0 license is a permissive, OSI-approved license that allows use, modification, and distribution for any purpose — personal, educational, or commercial — provided you include the license notice and state any significant changes. It also includes an explicit patent grant, which makes it well-suited for infrastructure and security tooling.

## What is covered

All EdgeShield code is licensed under Apache 2.0, including:

- `edgeshield-common`
- `edgeshield-config`
- `edgeshield-telemetry`
- `edgeshield-packet`
- `edgeshield-protocol`
- `edgeshield-storage`
- `edgeshield-discovery`
- `edgeshield-rules`
- `edgeshield-notify`
- `edgeshield-api`
- `edgeshield-daemon`
- `edgeshield-cli`
- `edgeshield-tui`
- `edgeshield-oui`

## Permitted Use

You may:

- **Use** EdgeShield for any purpose, including commercial products and internal monitoring.
- **Modify** the source code and distribute modifications under the terms of Apache 2.0.
- **Redistribute** EdgeShield, in whole or in part, provided the license notice is included.
- **Distribute** derivative works, provided you state any significant changes made to the original work (per Apache 2.0 §4(b)).

## Plugin Licensing

EdgeShield's future plugin system will support both open-source and commercial plugins.

### Open-source plugins

Plugins distributed under an OSI-approved open-source license (Apache 2.0, MIT, BSD, GPL) are welcome and encouraged. They are subject to the same contribution guidelines as core EdgeShield code.

### Commercial plugins

Plugins distributed under a proprietary license are permitted. The plugin API is designed to be license-agnostic. Commercial plugins must:

1. Clearly indicate their license in the plugin manifest
2. Not modify or sublicense the EdgeShield core
3. Comply with the EdgeShield plugin API terms

### Plugin API license

The EdgeShield plugin API (traits, types, and interfaces in `edgeshield-common` and related crates) is licensed under Apache 2.0, regardless of the plugin's license. This ensures that plugin authors can depend on a stable, permissively-licensed interface.

## License Compatibility

| Component | License | Compatible With |
|-----------|---------|-----------------|
| EdgeShield core | Apache 2.0 | All uses |
| Open-source plugins | OSI-approved | All uses |
| Commercial plugins | Proprietary | Commercial license required |
| Plugin API | Apache 2.0 | All uses |

## Frequently Asked Questions

**Q: Can I use EdgeShield in my commercial product?**

Yes. The Apache 2.0 license permits use in commercial products. You must include the license notice.

**Q: Can I redistribute EdgeShield?**

Yes, under the terms of the Apache 2.0 license. You must include the license notice and state any significant changes you made to the original work.

**Q: Do I need a separate license for internal use at my company?**

No. EdgeShield is free for all use, including internal commercial use.

**Q: Can I sell a plugin for EdgeShield?**

Yes. The plugin API is permissively licensed under Apache 2.0. You can sell plugins under any license you choose.

**Q: Why Apache 2.0 instead of MIT?**

Apache 2.0 includes an explicit patent grant and a requirement to state significant changes, which provides stronger protection for both users and contributors. It is the license used by many foundational Rust ecosystem projects and is fully compatible with MIT-licensed dependencies.