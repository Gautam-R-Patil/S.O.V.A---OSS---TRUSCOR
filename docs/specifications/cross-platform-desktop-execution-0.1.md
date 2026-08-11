<!-- status: implemented -->

# Cross-platform accessibility-first desktop execution 0.1

The desktop contract exposes `computer.snapshot`, `computer.click`, and
`computer.type` with application binding, exact accessibility locators,
before/after observations, evidence digests, cancellation, and explicit
provider limitations.

| Platform | Adapter | Binding |
| --- | --- | --- |
| Windows | Appium Windows driver | exact executable beneath the admitted fixture workspace |
| macOS | Appium Mac2 driver | exact bundle identifier |
| Linux | AT-SPI over the user's D-Bus accessibility session | exact application name and unambiguous role/name |

Coordinates, shell execution, arbitrary WebDriver scripts, broad process
control, and host-path escape are not part of this contract. Appium endpoints
must be credential-free loopback HTTP; SOVA validates W3C session and element
identifiers and captures UI source before and after mutation. The AT-SPI
backend bounds tree depth and node count and rejects absent or ambiguous
locators.

Platform drivers and accessibility trees are observation providers. They may
omit custom-drawn, GPU, elevated, secure-desktop, remote, or inaccessible UI.
Ordinary desktop automation is not containment. A platform is not release-
accepted until its real driver, owned native fixture, effect verification, and
cleanup receipt pass on that operating system.

Primary references: [Appium Windows driver](https://github.com/appium/appium-windows-driver),
[Appium Mac2 driver](https://github.com/appium/appium-mac2-driver), and
[Ubuntu AT-SPI architecture](https://ubuntu.com/desktop/docs/en/latest/explanation/accessibility-stack/).
