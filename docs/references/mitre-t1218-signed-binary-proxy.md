---
source_url: https://attack.mitre.org/techniques/T1218/
retrieved: 2026-06-06
fetched_with: scrapling extract get --ai-targeted
trust: UNTRUSTED third-party content captured for DFIR claim substantiation; verify against the live source before relying. Copyright remains with the original publisher.
---

> Source: https://attack.mitre.org/techniques/T1218/
> Retrieved 2026-06-06 via Scrapling (get).

---

[![ATT&CK Home](/theme/images/mitre_attack_logo.png)](/)




* [**Matrices**](/matrices/)

  [Enterprise](/matrices/enterprise/)
  [Mobile](/matrices/mobile/)
  [ICS](/matrices/ics/)
* [**Tactics**](/tactics/)

  [Enterprise](/tactics/enterprise/)
  [Mobile](/tactics/mobile/)
  [ICS](/tactics/ics/)
* [**Techniques**](/techniques/)

  [Enterprise](/techniques/enterprise/)
  [Mobile](/techniques/mobile/)
  [ICS](/techniques/ics/)
* [**Defenses**](/mitigations)

  [**Mitigations**](/mitigations/)

  [Enterprise](/mitigations/enterprise/)
  [Mobile](/mitigations/mobile/)
  [ICS](/mitigations/ics/)

  [Assets](/assets)

  [**Detections**](/detectionstrategies/)

  [Detection Strategies](/detectionstrategies/)
  [Analytics](/analytics/)
  [Data Components](/datacomponents)
* [**CTI**](/groups)

  [Groups](/groups)
  [Software](/software)
  [Campaigns](/campaigns)
* [**Resources**](/resources/)

  [Get Started](/resources/)
  [Learn More about ATT&CK](/resources/learn-more-about-attack/)
  [ATT&CK Advisory Council](/resources/attack-advisory-council/)
  [ATT&CKcon](/resources/attackcon/)
  [ATT&CK Data & Tools](/resources/attack-data-and-tools/)
  [FAQ](/resources/faq/)
  [Engage with ATT&CK](/resources/engage-with-attack/contact/)
  [Version History](/resources/versions/)
  [Updates](/resources/updates/)
  [Legal & Branding](/resources/legal-and-branding/)
* [**Benefactors**](/resources/engage-with-attack/benefactors/)
* [**Contribute**](/resources/engage-with-attack/contribute/)
* [**Blog** 
  ![External site](/theme/images/external-site.svg)](https://medium.com/mitre-attack/)
* Search

ATT&CKcon 7.0 is coming October 27-28, 2026. Learn more about [ATT&CKcon 7.0](https://attack.mitre.org/resources/attackcon/october-2026/) and [submit your proposal](https://www.openconf.org/ATTACKcon2026/).

1. [Home](/)
2. [Techniques](/techniques/enterprise)
3. [Enterprise](/techniques/enterprise)
4. System Binary Proxy Execution

System Binary Proxy Execution
=============================

##### Sub-techniques (14)

| ID | Name |
| --- | --- |
| [T1218.001](/techniques/T1218/001/) | [Compiled HTML File](/techniques/T1218/001/) |
| [T1218.002](/techniques/T1218/002/) | [Control Panel](/techniques/T1218/002/) |
| [T1218.003](/techniques/T1218/003/) | [CMSTP](/techniques/T1218/003/) |
| [T1218.004](/techniques/T1218/004/) | [InstallUtil](/techniques/T1218/004/) |
| [T1218.005](/techniques/T1218/005/) | [Mshta](/techniques/T1218/005/) |
| [T1218.007](/techniques/T1218/007/) | [Msiexec](/techniques/T1218/007/) |
| [T1218.008](/techniques/T1218/008/) | [Odbcconf](/techniques/T1218/008/) |
| [T1218.009](/techniques/T1218/009/) | [Regsvcs/Regasm](/techniques/T1218/009/) |
| [T1218.010](/techniques/T1218/010/) | [Regsvr32](/techniques/T1218/010/) |
| [T1218.011](/techniques/T1218/011/) | [Rundll32](/techniques/T1218/011/) |
| [T1218.012](/techniques/T1218/012/) | [Verclsid](/techniques/T1218/012/) |
| [T1218.013](/techniques/T1218/013/) | [Mavinject](/techniques/T1218/013/) |
| [T1218.014](/techniques/T1218/014/) | [MMC](/techniques/T1218/014/) |
| [T1218.015](/techniques/T1218/015/) | [Electron Applications](/techniques/T1218/015/) |

Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system.[[1]](https://github.com/LOLBAS-Project/LOLBAS#criteria) Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.

Similarly, on Linux systems adversaries may abuse trusted binaries such as `split` to proxy execution of malicious commands.[[2]](https://man7.org/linux/man-pages/man1/split.1.html)[[3]](https://gtfobins.github.io/gtfobins/split/)

ID: T1218

Sub-techniques: 
[T1218.001](/techniques/T1218/001), [T1218.002](/techniques/T1218/002), [T1218.003](/techniques/T1218/003), [T1218.004](/techniques/T1218/004), [T1218.005](/techniques/T1218/005), [T1218.007](/techniques/T1218/007), [T1218.008](/techniques/T1218/008), [T1218.009](/techniques/T1218/009), [T1218.010](/techniques/T1218/010), [T1218.011](/techniques/T1218/011), [T1218.012](/techniques/T1218/012), [T1218.013](/techniques/T1218/013), [T1218.014](/techniques/T1218/014), [T1218.015](/techniques/T1218/015)

ⓘ

Tactic:
[Stealth](/tactics/TA0005)

ⓘ

Platforms: Linux, Windows, macOS

Contributors: Hans Christoffer Gaardløs; Nishan Maharjan, @loki248; Praetorian; Wes Hurd

Version: 4.0

Created: 18 April 2018

Last Modified: 12 May 2026

[Version Permalink](/versions/v19/techniques/T1218/ "Permalink to this version of T1218")

[Live Version](/versions/v19/techniques/T1218/ "Go to the live version of T1218")

Procedure Examples
------------------

| ID | Name | Description |
| --- | --- | --- |
| [G0032](/groups/G0032) | [Lazarus Group](/groups/G0032) | [Lazarus Group](/groups/G0032) lnk files used for persistence have abused the Windows Update Client (`wuauclt.exe`) to execute a malicious DLL.[[4]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)[[5]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns) |
| [G1017](/groups/G1017) | [Volt Typhoon](/groups/G1017) | [Volt Typhoon](/groups/G1017) has used native tools and processes including living off the land binaries or "LOLBins" to maintain and expand access to the victim networks.[[6]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf) |

Mitigations
-----------

| ID | Mitigation | Description |
| --- | --- | --- |
| [M1042](/mitigations/M1042) | [Disable or Remove Feature or Program](/mitigations/M1042) | Many native binaries may not be necessary within a given environment. |
| [M1038](/mitigations/M1038) | [Execution Prevention](/mitigations/M1038) | Consider using application control to prevent execution of binaries that are susceptible to abuse and not required for a given system or network. |
| [M1050](/mitigations/M1050) | [Exploit Protection](/mitigations/M1050) | Microsoft's Enhanced Mitigation Experience Toolkit (EMET) Attack Surface Reduction (ASR) feature can be used to block methods of using using trusted binaries to bypass application control. |
| [M1037](/mitigations/M1037) | [Filter Network Traffic](/mitigations/M1037) | Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic. |
| [M1026](/mitigations/M1026) | [Privileged Account Management](/mitigations/M1026) | Restrict execution of particularly vulnerable binaries to privileged accounts or groups that need to use it to lessen the opportunities for malicious usage. |
| [M1021](/mitigations/M1021) | [Restrict Web-Based Content](/mitigations/M1021) | Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc. |

Detection Strategy
------------------

| ID | Name | Analytic ID | Analytic Description |
| --- | --- | --- | --- |
| [DET0081](/detectionstrategies/DET0081) | [Detection of Proxy Execution via Trusted Signed Binaries Across Platforms](/detectionstrategies/DET0081) | [AN0226](/detectionstrategies/DET0081#AN0226) | Execution of trusted, Microsoft-signed binaries such as `rundll32.exe`, `msiexec.exe`, or `regsvr32.exe` used to execute externally hosted, unsigned, or suspicious payloads through command-line parameters or network retrieval. |
| [AN0227](/detectionstrategies/DET0081#AN0227) | Execution of trusted system binaries (e.g., `split`, `tee`, `bash`, `env`) used in uncommon sequences or chained behaviors to execute malicious payloads or perform actions inconsistent with normal system or script behavior. |
| [AN0228](/detectionstrategies/DET0081#AN0228) | Use of system binaries such as `osascript`, `bash`, or `curl` to download or execute unsigned code or files in conjunction with application proxying. |

References
----------

1. [Oddvar Moe et al. (2022, February). Living Off The Land Binaries, Scripts and Libraries. Retrieved March 7, 2022.](https://github.com/LOLBAS-Project/LOLBAS#criteria)
2. [Torbjorn Granlund, Richard M. Stallman. (2020, March null). split(1) — Linux manual page. Retrieved March 25, 2022.](https://man7.org/linux/man-pages/man1/split.1.html)
3. [GTFOBins. (2020, November 13). split. Retrieved April 18, 2022.](https://gtfobins.github.io/gtfobins/split/)

1. [Saini, A. and Hossein, J. (2022, January 27). North Korea’s Lazarus APT leverages Windows Update client, GitHub in latest campaign. Retrieved January 27, 2022.](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)
2. [Pradhan, A. (2022, February 8). LolZarus: Lazarus Group Incorporating Lolbins into Campaigns. Retrieved March 22, 2022.](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)
3. [CISA et al.. (2024, February 7). PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure. Retrieved May 15, 2024.](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)

[![](/theme/images/mitrelogowhiteontrans.gif)](https://www.mitre.org)

[Contact Us](/resources/engage-with-attack/contact)

[Terms of Use](/resources/legal-and-branding/terms-of-use)

[Privacy Policy](/resources/legal-and-branding/privacy)

[Website Changelog](/resources/changelog.html "ATT&CK content v19.1Website  v4.4.3")

[Cookie Preferences](/resources/legal-and-branding/privacy/#)

© 2015 - 2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.