# Code of conduct

This project follows the [Contributor Covenant, version 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

In short: be decent. Assume the other person is acting in good faith until they prove otherwise. Critique the code and the claim, not the person. No harassment, no personal attacks, no dismissiveness dressed up as rigour.

Two things specific to a security project:

- **Do not publish someone else's bypass without a fix or a disclosure window.** Report it privately first; see [SECURITY.md](SECURITY.md).
- **Do not ship weaponised payloads** in a pull request: no live exfiltration endpoints, no real credentials, no code aimed at a third party's system.

Enforcement: a maintainer may edit, remove or reject contributions, and may block accounts for behaviour that makes the project harder to work on. Reports go to the maintainer listed in `package.json` and are handled privately.

This is a text file, not a police force. If someone is being unpleasant and nothing happens, say so publicly and carry on with the work; that has proven more effective than most enforcement.
