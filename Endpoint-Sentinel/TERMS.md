# Endpoint Sentinel Terms and Software Disclaimer

**Last updated: November 24, 2026**

These terms apply to the Endpoint Sentinel prototype, including its source code and any builds or documentation provided with it ("Software"). By using the Software, you acknowledge these limitations. If you do not accept them, do not install or use it.

## Prototype only; no security guarantee

The Software is an experimental, prototype security companion provided for evaluation and development. It is not a finished, supported, or production-ready security product, and it is not medical, legal, or professional security advice.

The Software does **not** guarantee detection or prevention of malware, intrusions, data loss, or other threats, and does not guarantee that any computer, file, network, or data is safe. Its included scanner looks only for a documented harmless test marker; it is not a malware-detection engine. Monitoring is limited and best effort, and events or files can be missed or left uninspected.

The Software does not provide a real antivirus engine, threat-removal service, quarantine, or remediation. It does not delete or alter inspected files, execute them, change Microsoft Defender settings, or initiate Defender scans. An alert is not proof of malware, and no alert is not proof of safety.

## Scope and operation

The Software performs local, read-only inspection and status reporting. The optional Windows Service monitors only explicitly configured directories, at the top level, and only while running. The desktop and service do not share a database. Operation depends on Windows, available permissions, configuration, and other system conditions; any of these can prevent or limit inspection.

## Data and privacy

The current implementation does not upload files or scan results, and has no cloud lookup, account, or telemetry feature. Files are inspected locally and are not copied, executed, or modified by the scanner.

The Software stores limited operational data on the device: scan-history summaries in the current user's `%LOCALAPPDATA%\EndpointSentinel\scan-history.json`, and service configuration and event logs under `%ProgramData%\EndpointSentinel\`. Summaries and logs can include file or directory paths, finding labels, hashes, timestamps, status, and error details. The service's configuration contains the monitored paths you choose. Windows permissions, backups, other software, or people with access to the device may also expose this data. You are responsible for reviewing, protecting, and deleting local data and for setting appropriate access controls.

## Permissions and installation

Use the Software only on devices and files you own or are authorized to administer or monitor. You are responsible for choosing appropriate directories, reviewing the service configuration and Windows access-control lists (ACLs), and ensuring that the service identity has only the access it needs. Installing or controlling the optional Windows Service requires elevated permissions. Installation, configuration, and use are your responsibility; the Software does not validate that you have authority over a device or its data.

## Acceptable use

Use the Software lawfully and only for authorized defensive testing, evaluation, and local monitoring. Do not use it to access, inspect, or monitor another person's device or data without authorization, or in a way that violates applicable law, privacy rights, or third-party terms. Do not rely on it as the sole protection for any device or information.

## Windows, Microsoft Defender, and other third parties

Microsoft Defender and Windows are separate products, not part of this Software. Defender status values are reported by Windows and may be unavailable, stale, incomplete, or inaccurate. The Software does not enable, configure, or verify the effectiveness of Defender or any other security control. Keep trusted endpoint protection enabled, use Windows Security and the operating system for protection and remediation, and follow their documentation and applicable third-party terms. The authors do not control or warrant Windows, Defender, other software, or third-party services.

## No warranty

To the maximum extent permitted by applicable law, the Software is provided **"AS IS" and "AS AVAILABLE," without warranties or conditions of any kind**, whether express, implied, or statutory, including warranties of merchantability, fitness for a particular purpose, title, non-infringement, accuracy, availability, or that the Software will detect threats, operate without interruption, or meet your requirements. Some jurisdictions do not allow certain warranty exclusions, so some of these exclusions may not apply to you.

## Limitation of liability

To the maximum extent permitted by applicable law, no author or contributor will be liable for indirect, incidental, special, consequential, exemplary, or punitive damages, or for loss of data, profits, goodwill, or business interruption, arising out of or relating to the Software or these terms, even if advised that such damages are possible. To the maximum extent permitted by law, the authors' and contributors' total liability for all claims relating to the Software will not exceed the amount you paid specifically for the Software, if any.

Nothing in these terms excludes or limits liability that applicable law does not allow to be excluded or limited. These terms describe intended risk allocation; they do not eliminate liability or guarantee that any limitation will be enforceable in every jurisdiction.

## Changes and legal review

The Software and these terms may change as the prototype develops. Check this document when updating or using a new version. These terms are a general software disclaimer, not legal advice, and have not been prepared or reviewed by a lawyer. Obtain professional legal review for your jurisdiction and intended distribution or use before relying on them.
