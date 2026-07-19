# Licensing

EdgeShield uses a dual-licensing model to support both the open-source community and commercial users.

## Community Edition

The Community Edition of EdgeShield is licensed under your choice of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

This is the same licensing model used by Rust, Tokio, and many other foundational Rust projects. You may use, modify, and distribute the Community Edition for any purpose — personal, educational, or commercial — without restriction, provided you include the appropriate license notice.

### What is included

All code in the following crates is available under the Community Edition license:

- `edgeshield-common`
- `edgeshield-config`
- `edgeshield-telemetry`
- `edgeshield-packet`
- `edgeshield-protocol`
- `edgeshield-storage`
- `edgeshield-discovery`
- `edgeshield-api`
- `edgeshield-daemon`
- `edgeshield-cli`

## Commercial Edition

The Commercial Edition of EdgeShield is licensed under a proprietary license. It includes all Community Edition features plus additional capabilities designed for organizational use.

### Commercial features

- **Multi-tenant support**: Isolated network segments for different teams or clients
- **Advanced detection**: Signature-based and behavioral detection rules
- **Enterprise authentication**: LDAP, SAML, OAuth2, SSO
- **Role-based access control**: Granular permissions for users and roles
- **SIEM integration**: Syslog, Common Event Format (CEF), and webhook output
- **High availability**: Active-passive failover configuration
- **SLA support**: Guaranteed response times and uptime commitments
- **Custom branding**: White-label dashboard and reports

### Commercial licensing

Commercial licenses are available on a per-instance or per-organization basis. Contact **licensing@edgeshield.io** for pricing and terms.

## Premium Features

Some features may be available as premium add-ons for Community Edition users. These are individual features that can be purchased without a full Commercial Edition license.

### Planned premium features

- **Historical graphs**: 30-day traffic history with 1-minute resolution
- **Alert webhooks**: Slack, Discord, PagerDuty, email integration
- **Advanced reporting**: PDF/CSV export of network reports
- **API rate limit increase**: Higher rate limits for API access

## Plugin Licensing

EdgeShield's future plugin system will support both open-source and commercial plugins.

### Open-source plugins

Plugins distributed under an OSI-approved open-source license (MIT, Apache 2.0, BSD, GPL) are welcome and encouraged. They are subject to the same contribution guidelines as core EdgeShield code.

### Commercial plugins

Plugins distributed under a proprietary license are permitted. The plugin API is designed to be license-agnostic. Commercial plugins must:

1. Clearly indicate their license in the plugin manifest
2. Not modify or sublicense the EdgeShield core
3. Comply with the EdgeShield plugin API terms

### Plugin API license

The EdgeShield plugin API (traits, types, and interfaces in `edgeshield-common` and related crates) is licensed under MIT/Apache 2.0, regardless of the plugin's license. This ensures that plugin authors can depend on a stable, permissively-licensed interface.

## License Compatibility

| Component | License | Compatible With |
|-----------|---------|-----------------|
| Community Edition | MIT / Apache 2.0 | All uses |
| Commercial Edition | Proprietary | Commercial license required |
| Open-source plugins | OSI-approved | All uses |
| Commercial plugins | Proprietary | Commercial license required |
| Plugin API | MIT / Apache 2.0 | All uses |

## Frequently Asked Questions

**Q: Can I use the Community Edition in my commercial product?**

Yes. The MIT and Apache 2.0 licenses permit use in commercial products. You must include the license notice.

**Q: Can I redistribute EdgeShield Community Edition?**

Yes, under the terms of the MIT or Apache 2.0 license.

**Q: Do I need a commercial license if I'm using EdgeShield for internal monitoring at my company?**

No. The Community Edition is free for all use, including internal commercial use. The Commercial Edition is only needed for the additional features listed above.

**Q: Can I sell a plugin for EdgeShield?**

Yes. The plugin API is permissively licensed. You can sell plugins under any license you choose.

**Q: What happens if I stop paying for the Commercial Edition?**

You may continue using the version you have licensed. You will not receive updates or support. You may revert to the Community Edition at any time.
