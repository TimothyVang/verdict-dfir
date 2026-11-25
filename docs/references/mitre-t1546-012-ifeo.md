---
source_url: https://attack.mitre.org/techniques/T1546/012/
retrieved: 2026-06-06
fetched_with: scrapling extract get --ai-targeted
trust: UNTRUSTED third-party content captured for DFIR claim substantiation; verify against the live source before relying. Copyright remains with the original publisher.
---

> Source: https://attack.mitre.org/techniques/T1546/012/
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
4. [Event Triggered Execution](/techniques/T1546)
5. Image File Execution Options Injection

Event Triggered Execution:
Image File Execution Options Injection
=================================================================

##### Other sub-techniques of Event Triggered Execution (18)

| ID | Name |
| --- | --- |
| [T1546.001](/techniques/T1546/001/) | [Change Default File Association](/techniques/T1546/001/) |
| [T1546.002](/techniques/T1546/002/) | [Screensaver](/techniques/T1546/002/) |
| [T1546.003](/techniques/T1546/003/) | [Windows Management Instrumentation Event Subscription](/techniques/T1546/003/) |
| [T1546.004](/techniques/T1546/004/) | [Unix Shell Configuration Modification](/techniques/T1546/004/) |
| [T1546.005](/techniques/T1546/005/) | [Trap](/techniques/T1546/005/) |
| [T1546.006](/techniques/T1546/006/) | [LC\_LOAD\_DYLIB Addition](/techniques/T1546/006/) |
| [T1546.007](/techniques/T1546/007/) | [Netsh Helper DLL](/techniques/T1546/007/) |
| [T1546.008](/techniques/T1546/008/) | [Accessibility Features](/techniques/T1546/008/) |
| [T1546.009](/techniques/T1546/009/) | [AppCert DLLs](/techniques/T1546/009/) |
| [T1546.010](/techniques/T1546/010/) | [AppInit DLLs](/techniques/T1546/010/) |
| [T1546.011](/techniques/T1546/011/) | [Application Shimming](/techniques/T1546/011/) |
| T1546.012 | Image File Execution Options Injection |
| [T1546.013](/techniques/T1546/013/) | [PowerShell Profile](/techniques/T1546/013/) |
| [T1546.014](/techniques/T1546/014/) | [Emond](/techniques/T1546/014/) |
| [T1546.015](/techniques/T1546/015/) | [Component Object Model Hijacking](/techniques/T1546/015/) |
| [T1546.016](/techniques/T1546/016/) | [Installer Packages](/techniques/T1546/016/) |
| [T1546.017](/techniques/T1546/017/) | [Udev Rules](/techniques/T1546/017/) |
| [T1546.018](/techniques/T1546/018/) | [Python Startup Hooks](/techniques/T1546/018/) |

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., `C:\dbg\ntsd.exe -g notepad.exe`).[[1]](https://blogs.msdn.microsoft.com/mithuns/2010/03/24/image-file-execution-options-ifeo/)

IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool.[[2]](https://docs.microsoft.com/windows-hardware/drivers/debugger/gflags-overview) IFEOs are represented as `Debugger` values in the Registry under `HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` where `<executable>` is the binary on which the debugger is attached.[[1]](https://blogs.msdn.microsoft.com/mithuns/2010/03/24/image-file-execution-options-ifeo/)

IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process).[[3]](https://docs.microsoft.com/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit)[[4]](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/) Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\`.[[3]](https://docs.microsoft.com/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit)[[4]](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)

Similar to [Accessibility Features](/techniques/T1546/008), on Windows Vista and later as well as Windows Server 2008 and later, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for an accessibility program (ex: utilman.exe). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with [Remote Desktop Protocol](/techniques/T1021/001) will cause the "debugger" program to be executed with SYSTEM privileges.[[5]](https://web.archive.org/web/20200730053039/https://www.crowdstrike.com/blog/registry-analysis-with-crowdresponse/)

Similar to [Process Injection](/techniques/T1055), these values may also be abused to obtain privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer.[[6]](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process) Installing IFEO mechanisms may also provide Persistence via continuous triggered invocation.

Malware may also use IFEO to impair defenses by registering invalid debuggers that redirect and effectively disable various system and security applications.[[7]](https://www.f-secure.com/v-descs/backdoor_w32_hupigon_emv.shtml)[[8]](https://www.symantec.com/security_response/writeup.jsp?docid=2008-062807-2501-99&tabid=2)

ID: T1546.012

Sub-technique of: 
[T1546](/techniques/T1546)

ⓘ

Tactics:
[Privilege Escalation](/tactics/TA0004), [Persistence](/tactics/TA0003)

ⓘ

Platforms: Windows

Contributors: Oddvar Moe, @oddvarmoe

Version: 1.2

Created: 24 January 2020

Last Modified: 12 May 2026

[Version Permalink](/versions/v19/techniques/T1546/012/ "Permalink to this version of T1546.012")

[Live Version](/versions/v19/techniques/T1546/012/ "Go to the live version of T1546.012")

Procedure Examples
------------------

| ID | Name | Description |
| --- | --- | --- |
| [C0032](/campaigns/C0032) | [C0032](/campaigns/C0032) | During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](/groups/G0088) modified and added entries within `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` to maintain persistence.[[9]](https://www.fireeye.com/blog/threat-research/2019/04/triton-actor-ttp-profile-custom-attack-tools-detections.html) |
| [S0461](/software/S0461) | [SDBbot](/software/S0461) | [SDBbot](/software/S0461) has the ability to use image file execution options for persistence if it detects it is running with admin privileges on a Windows version newer than Windows 7.[[10]](https://www.proofpoint.com/us/threat-insight/post/ta505-distributes-new-sdbbot-remote-access-trojan-get2-downloader) |
| [S0559](/software/S0559) | [SUNBURST](/software/S0559) | [SUNBURST](/software/S0559) created an Image File Execution Options (IFEO) Debugger registry value for the process `dllhost.exe` to trigger the installation of [Cobalt Strike](/software/S0154).[[11]](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/) |

Mitigations
-----------

This type of attack technique cannot be easily mitigated with preventive controls since
it is based on the abuse of system features.

Detection Strategy
------------------

| ID | Name | Analytic ID | Analytic Description |
| --- | --- | --- | --- |
| [DET0422](/detectionstrategies/DET0422) | [Detection Strategy for IFEO Injection on Windows](/detectionstrategies/DET0422) | [AN1186](/detectionstrategies/DET0422#AN1186) | Registry key modifications under IFEO paths (e.g., Debugger value set under Image File Execution Options), especially for security-related or accessibility binaries, followed by anomalous process execution with debugger flags or SYSTEM-level access at login. Detectable by correlating registry modifications, process creation, and parent-child anomalies with unusual command-line usage or access tokens. |

References
----------

1. [Shanbhag, M. (2010, March 24). Image File Execution Options (IFEO). Retrieved December 18, 2017.](https://blogs.msdn.microsoft.com/mithuns/2010/03/24/image-file-execution-options-ifeo/)
2. [Microsoft. (2017, May 23). GFlags Overview. Retrieved December 18, 2017.](https://docs.microsoft.com/windows-hardware/drivers/debugger/gflags-overview)
3. [Marshall, D. & Griffin, S. (2017, November 28). Monitoring Silent Process Exit. Retrieved June 27, 2018.](https://docs.microsoft.com/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit)
4. [Moe, O. (2018, April 10). Persistence using GlobalFlags in Image File Execution Options - Hidden from Autoruns.exe. Retrieved June 27, 2018.](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)
5. [Tilbury, C. (2014, August 28). Registry Analysis with CrowdResponse. Retrieved November 17, 2024.](https://web.archive.org/web/20200730053039/https://www.crowdstrike.com/blog/registry-analysis-with-crowdresponse/)
6. [Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

1. [FSecure. (n.d.). Backdoor - W32/Hupigon.EMV - Threat Description. Retrieved December 18, 2017.](https://www.f-secure.com/v-descs/backdoor_w32_hupigon_emv.shtml)
2. [Symantec. (2008, June 28). Trojan.Ushedix. Retrieved December 18, 2017.](https://www.symantec.com/security_response/writeup.jsp?docid=2008-062807-2501-99&tabid=2)
3. [Miller, S, et al. (2019, April 10). TRITON Actor TTP Profile, Custom Attack Tools, Detections, and ATT&CK Mapping. Retrieved April 16, 2019.](https://www.fireeye.com/blog/threat-research/2019/04/triton-actor-ttp-profile-custom-attack-tools-detections.html)
4. [Schwarz, D. et al. (2019, October 16). TA505 Distributes New SDBbot Remote Access Trojan with Get2 Downloader. Retrieved May 29, 2020.](https://www.proofpoint.com/us/threat-insight/post/ta505-distributes-new-sdbbot-remote-access-trojan-get2-downloader)
5. [MSTIC, CDOC, 365 Defender Research Team. (2021, January 20). Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop . Retrieved January 22, 2021.](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)

[![](/theme/images/mitrelogowhiteontrans.gif)](https://www.mitre.org)

[Contact Us](/resources/engage-with-attack/contact)

[Terms of Use](/resources/legal-and-branding/terms-of-use)

[Privacy Policy](/resources/legal-and-branding/privacy)

[Website Changelog](/resources/changelog.html "ATT&CK content v19.1Website  v4.4.3")

[Cookie Preferences](/resources/legal-and-branding/privacy/#)

© 2015 - 2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.