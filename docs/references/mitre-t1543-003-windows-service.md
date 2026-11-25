---
source_url: https://attack.mitre.org/techniques/T1543/003/
retrieved: 2026-06-06
fetched_with: scrapling extract get --ai-targeted
trust: UNTRUSTED third-party content captured for DFIR claim substantiation; verify against the live source before relying. Copyright remains with the original publisher.
---

> Source: https://attack.mitre.org/techniques/T1543/003/
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
4. [Create or Modify System Process](/techniques/T1543)
5. Windows Service

Create or Modify System Process:
Windows Service
================================================

##### Other sub-techniques of Create or Modify System Process (5)

| ID | Name |
| --- | --- |
| [T1543.001](/techniques/T1543/001/) | [Launch Agent](/techniques/T1543/001/) |
| [T1543.002](/techniques/T1543/002/) | [Systemd Service](/techniques/T1543/002/) |
| T1543.003 | Windows Service |
| [T1543.004](/techniques/T1543/004/) | [Launch Daemon](/techniques/T1543/004/) |
| [T1543.005](/techniques/T1543/005/) | [Container Service](/techniques/T1543/005/) |

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.[[1]](https://technet.microsoft.com/en-us/library/cc772408.aspx) Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.

Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities (such as sc.exe), by directly modifying the Registry, or by interacting directly with the Windows API.

Adversaries may also use services to install and execute malicious drivers. For example, after dropping a driver file (ex: `.sys`) to disk, the payload can be loaded and registered via [Native API](/techniques/T1106) functions such as `CreateServiceW()` (or manually via functions such as `ZwLoadDriver()` and `ZwSetValueKey()`), by creating the required service Registry values (i.e. [Modify Registry](/techniques/T1112)), or by using command-line utilities such as `PnPUtil.exe`.[[2]](https://www.wired.com/images_blogs/threatlevel/2010/11/w32_stuxnet_dossier.pdf)[[3]](https://www.crowdstrike.com/blog/how-crowdstrike-falcon-protects-against-wiper-malware-used-in-ukraine-attacks/)[[4]](https://unit42.paloaltonetworks.com/acidbox-rare-malware/) Adversaries may leverage these drivers as [Rootkit](/techniques/T1014)s to hide the presence of malicious activity on a system. Adversaries may also load a signed yet vulnerable driver onto a compromised machine (known as "Bring Your Own Vulnerable Driver" (BYOVD)) as part of [Exploitation for Privilege Escalation](/techniques/T1068).[[5]](https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf)[[4]](https://unit42.paloaltonetworks.com/acidbox-rare-malware/)

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges. Adversaries may also directly start services through [Service Execution](/techniques/T1569/002).

To make detection analysis more challenging, malicious services may also incorporate [Masquerade Task or Service](/techniques/T1036/004) (ex: using a service and/or payload name related to a legitimate OS or benign software component). Adversaries may also create ‘hidden’ services (i.e., [Hide Artifacts](/techniques/T1564)), for example by using the `sc sdset` command to set service permissions via the Service Descriptor Definition Language (SDDL). This may hide a Windows service from the view of standard service enumeration methods such as `Get-Service`, `sc query`, and `services.exe`.[[6]](https://www.sans.org/blog/red-team-tactics-hiding-windows-services/)[[7]](https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services/)

ID: T1543.003

Sub-technique of: 
[T1543](/techniques/T1543)

ⓘ

Tactics:
[Persistence](/tactics/TA0003), [Privilege Escalation](/tactics/TA0004)

ⓘ

Platforms: Windows

Contributors: Akshat Pradhan, Qualys; Matthew Demaske, Adaptforward; Mayuresh Dani, Qualys; Pedro Harrison; Wietze Beukema @Wietze; Wirapong Petshagun

Version: 1.6

Created: 17 January 2020

Last Modified: 12 May 2026

[Version Permalink](/versions/v19/techniques/T1543/003/ "Permalink to this version of T1543.003")

[Live Version](/versions/v19/techniques/T1543/003/ "Go to the live version of T1543.003")

Procedure Examples
------------------

| ID | Name | Description |
| --- | --- | --- |
| [C0025](/campaigns/C0025) | [2016 Ukraine Electric Power Attack](/campaigns/C0025) | During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](/groups/G0034) used an arbitrary system service to load at system boot for persistence for [Industroyer](/software/S0604). They also replaced the ImagePath registry value of a Windows service with a new backdoor binary. [[8]](https://dragos.com/blog/crashoverride/CrashOverride-01.pdf) |
| [G1030](/groups/G1030) | [Agrius](/groups/G1030) | [Agrius](/groups/G1030) has deployed [IPsec Helper](/software/S1132) malware post-exploitation and registered it as a service for persistence.[[9]](https://assets.sentinelone.com/sentinellabs/evol-agrius) |
| [S0504](/software/S0504) | [Anchor](/software/S0504) | [Anchor](/software/S0504) can establish persistence by creating a service.[[10]](https://www.cybereason.com/blog/dropping-anchor-from-a-trickbot-infection-to-the-discovery-of-the-anchor-malware) |
| [S0584](/software/S0584) | [AppleJeus](/software/S0584) | [AppleJeus](/software/S0584) can install itself as a service.[[11]](https://us-cert.cisa.gov/ncas/alerts/aa21-048a) |
| [G0073](/groups/G0073) | [APT19](/groups/G0073) | An [APT19](/groups/G0073) Port 22 malware variant registers itself as a service.[[12]](https://researchcenter.paloaltonetworks.com/2016/01/new-attacks-linked-to-c0d0s0-group/) |
| [G0022](/groups/G0022) | [APT3](/groups/G0022) | [APT3](/groups/G0022) has a tool that creates a new service for persistence.[[13]](https://www.fireeye.com/blog/threat-research/2014/11/operation_doubletap.html) |
| [G0050](/groups/G0050) | [APT32](/groups/G0050) | [APT32](/groups/G0050) modified Windows Services to ensure PowerShell scripts were loaded on the system. [APT32](/groups/G0050) also creates a Windows service to establish persistence.[[14]](https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/)[[15]](https://cdn2.hubspot.net/hubfs/3354902/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty.pdf)[[16]](https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/) |
| [G0082](/groups/G0082) | [APT38](/groups/G0082) | [APT38](/groups/G0082) has installed a new Windows service to establish persistence.[[17]](https://us-cert.cisa.gov/ncas/alerts/aa20-239a) |
| [G0096](/groups/G0096) | [APT41](/groups/G0096) | [APT41](/groups/G0096) modified legitimate Windows services to install malware backdoors.[[18]](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf)[[19]](https://www.group-ib.com/blog/colunmtk-apt41/) [APT41](/groups/G0096) created the StorSyncSvc service to provide persistence for [Cobalt Strike](/software/S0154).[[20]](https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html) |
| [C0040](/campaigns/C0040) | [APT41 DUST](/campaigns/C0040) | [APT41 DUST](https://attack.mitre.org/campaigns/C0040) used Windows Services with names such as `Windows Defend` for persistence of [DUSTPAN](/software/S1158).[[21]](https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust) |
| [G0143](/groups/G0143) | [Aquatic Panda](/groups/G0143) | [Aquatic Panda](/groups/G0143) created new Windows services for persistence that masqueraded as legitimate Windows services via name change.[[22]](https://go.crowdstrike.com/rs/281-OBQ-266/images/2022OverWatchThreatHuntingReport.pdf) |
| [S0438](/software/S0438) | [Attor](/software/S0438) | [Attor](/software/S0438)'s dispatcher can establish persistence by registering a new service.[[23]](https://www.welivesecurity.com/wp-content/uploads/2019/10/ESET_Attor.pdf) |
| [S0347](/software/S0347) | [AuditCred](/software/S0347) | [AuditCred](/software/S0347) is installed as a new service on the system.[[24]](https://blog.trendmicro.com/trendlabs-security-intelligence/lazarus-continues-heists-mounts-attacks-on-financial-organizations-in-latin-america/) |
| [S0239](/software/S0239) | [Bankshot](/software/S0239) | [Bankshot](/software/S0239) can terminate a specific process by its process id.[[25]](https://securingtomorrow.mcafee.com/mcafee-labs/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant/)[[26]](https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-B_WHITE.PDF) |
| [S0127](/software/S0127) | [BBSRAT](/software/S0127) | [BBSRAT](/software/S0127) can modify service configurations.[[27]](http://researchcenter.paloaltonetworks.com/2015/12/bbsrat-attacks-targeting-russian-organizations-linked-to-roaming-tiger/) |
| [S0268](/software/S0268) | [Bisonal](/software/S0268) | [Bisonal](/software/S0268) has been modified to be used as a Windows service.[[28]](https://blog.talosintelligence.com/2020/03/bisonal-10-years-of-play.html) |
| [S0570](/software/S0570) | [BitPaymer](/software/S0570) | [BitPaymer](/software/S0570) has attempted to install itself as a service to maintain persistence.[[29]](https://www.crowdstrike.com/blog/big-game-hunting-the-evolution-of-indrik-spider-from-dridex-wire-fraud-to-bitpaymer-targeted-ransomware/) |
| [S1070](/software/S1070) | [Black Basta](/software/S1070) | [Black Basta](/software/S1070) can create a new service to establish persistence.[[30]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/)[[31]](https://www.avertium.com/resources/threat-reports/in-depth-look-at-black-basta-ransomware) |
| [G1043](/groups/G1043) | [BlackByte](/groups/G1043) | [BlackByte](/groups/G1043) modified multiple services on victim machines to enable encryption operations.[[32]](https://www.security.com/threat-intelligence/blackbyte-exbyte-ransomware) [BlackByte](/groups/G1043) has installed tools such as AnyDesk as a service on victim machines.[[33]](https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/) |
| [S0089](/software/S0089) | [BlackEnergy](/software/S0089) | One variant of [BlackEnergy](/software/S0089) creates a new service using either a hard-coded or randomly generated name.[[34]](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf) |
| [G0108](/groups/G0108) | [Blue Mockingbird](/groups/G0108) | [Blue Mockingbird](/groups/G0108) has made their XMRIG payloads persistent as a Windows Service.[[35]](https://redcanary.com/blog/blue-mockingbird-cryptominer/) |
| [S1226](/software/S1226) | [BOOKWORM](/software/S1226) | [BOOKWORM](/software/S1226) has created a service named `Microsoft Windows DeviceSync Service` at `HKLM\SYSTEM\CurrentControlSet\Services\DeviceSync\` to trigger execution when the system starts and to maintain persistence. [[36]](https://unit42.paloaltonetworks.com/bookworm-trojan-a-model-of-modular-architecture/) |
| [S0204](/software/S0204) | [Briba](/software/S0204) | [Briba](/software/S0204) installs a service pointing to a malicious DLL dropped to disk.[[37]](https://www.symantec.com/security_response/writeup.jsp?docid=2012-051515-2843-99) |
| [G0008](/groups/G0008) | [Carbanak](/groups/G0008) | [Carbanak](/groups/G0008) malware installs itself as a service to provide persistence and SYSTEM privileges.[[38]](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf) |
| [S0335](/software/S0335) | [Carbon](/software/S0335) | [Carbon](/software/S0335) establishes persistence by creating a service and naming it based off the operating system version running on the current machine.[[39]](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/) |
| [S0261](/software/S0261) | [Catchamas](/software/S0261) | [Catchamas](/software/S0261) adds a new service named NetAdapter to establish persistence.[[40]](https://web.archive.org/web/20190508165711/https://www-west.symantec.com/content/symantec/english/en/security-center/writeup.html/2018-040209-1742-99) |
| [G1021](/groups/G1021) | [Cinnamon Tempest](/groups/G1021) | [Cinnamon Tempest](/groups/G1021) has created system services to establish persistence for deployed tooling.[[41]](https://blog.sygnia.co/revealing-emperor-dragonfly-a-chinese-ransomware-group) |
| [S0660](/software/S0660) | [Clambling](/software/S0660) | [Clambling](/software/S0660) can register itself as a system service to gain persistence.[[42]](https://www.talent-jump.com/article/2020/02/17/CLAMBLING-A-New-Backdoor-Base-On-Dropbox-en/) |
| [G0080](/groups/G0080) | [Cobalt Group](/groups/G0080) | [Cobalt Group](/groups/G0080) has created new services to establish persistence.[[43]](https://www.group-ib.com/blog/cobalt) |
| [S0154](/software/S0154) | [Cobalt Strike](/software/S0154) | [Cobalt Strike](/software/S0154) can install a new service.[[44]](https://web.archive.org/web/20210924171429/https://www.cobaltstrike.com/downloads/reports/tacticstechniquesandprocedures.pdf) |
| [S0608](/software/S0608) | [Conficker](/software/S0608) | [Conficker](/software/S0608) copies itself into the `%systemroot%\system32` directory and registers as a service.[[45]](https://web.archive.org/web/20200125132645/https://www.sans.org/security-resources/malwarefaq/conficker-worm) |
| [S1235](/software/S1235) | [CorKLOG](/software/S1235) | [CorKLOG](/software/S1235) has created a service to establish persistence.[[46]](https://www.zscaler.com/blogs/security-research/latest-mustang-panda-arsenal-paklog-corklog-and-splatcloak-p2) |
| [S0050](/software/S0050) | [CosmicDuke](/software/S0050) | [CosmicDuke](/software/S0050) uses Windows services typically named "javamtsup" for persistence.[[47]](https://blog.f-secure.com/wp-content/uploads/2019/10/CosmicDuke.pdf) |
| [S0046](/software/S0046) | [CozyCar](/software/S0046) | One persistence mechanism used by [CozyCar](/software/S0046) is to register itself as a Windows service.[[48]](https://www.f-secure.com/documents/996508/1030745/CozyDuke) |
| [S0625](/software/S0625) | [Cuba](/software/S0625) | [Cuba](/software/S0625) can modify services by using the `OpenService` and `ChangeServiceConfig` functions.[[49]](https://www.mcafee.com/enterprise/en-us/assets/reports/rp-cuba-ransomware.pdf) |
| [G0105](/groups/G0105) | [DarkVishnya](/groups/G0105) | [DarkVishnya](/groups/G0105) created new services for shellcode loaders distribution.[[50]](https://securelist.com/darkvishnya/89169/) |
| [S1033](/software/S1033) | [DCSrv](/software/S1033) | [DCSrv](/software/S1033) has created new services for persistence by modifying the Registry.[[51]](https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/) |
| [S0567](/software/S0567) | [Dtrack](/software/S0567) | [Dtrack](/software/S0567) can add a service called WBService to establish persistence.[[52]](https://www.cyberbit.com/blog/endpoint-security/dtrack-apt-malware-found-in-nuclear-power-plant/) |
| [S0038](/software/S0038) | [Duqu](/software/S0038) | [Duqu](/software/S0038) creates a new service that loads a malicious driver when the system starts. When Duqu is active, the operating system believes that the driver is legitimate, as it has been signed with a valid private key.[[53]](https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/w32_duqu_the_precursor_to_the_next_stuxnet.pdf) |
| [S1158](/software/S1158) | [DUSTPAN](/software/S1158) | [DUSTPAN](/software/S1158) can persist as a Windows Service in operations.[[21]](https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust) |
| [S0024](/software/S0024) | [Dyre](/software/S0024) | [Dyre](/software/S0024) registers itself as a service by adding several Registry keys.[[54]](http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/dyre-emerging-threat.pdf) |
| [G1006](/groups/G1006) | [Earth Lusca](/groups/G1006) | [Earth Lusca](/groups/G1006) created a service using the command `sc create "SysUpdate" binpath= "cmd /c start "[file path]""&&sc config "SysUpdate" start= auto&&net start SysUpdate` for persistence.[[55]](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf) |
| [S0081](/software/S0081) | [Elise](/software/S0081) | [Elise](/software/S0081) configures itself as a service.[[56]](https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html) |
| [S1247](/software/S1247) | [Embargo](/software/S1247) | [Embargo](/software/S1247) has created persistence through the DLL variant of the MDeployer toolkit by creating a service called irnagentd that launches after the system is rebooted in Safe Mode.[[57]](https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/) |
| [S0082](/software/S0082) | [Emissary](/software/S0082) | [Emissary](/software/S0082) is capable of configuring itself as a service.[[58]](http://researchcenter.paloaltonetworks.com/2016/02/emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve/) |
| [S0367](/software/S0367) | [Emotet](/software/S0367) | [Emotet](/software/S0367) has been observed creating new services to maintain persistence.[[59]](https://www.us-cert.gov/ncas/alerts/TA18-201A)[[60]](https://www.secureworks.com/blog/lazy-passwords-become-rocket-fuel-for-emotet-smb-spreader)[[61]](https://www.binarydefense.com/resources/blog/emotet-evolves-with-new-wi-fi-spreader/) |
| [S0363](/software/S0363) | [Empire](/software/S0363) | [Empire](/software/S0363) can utilize built-in modules to modify service binaries and restore them to their original state.[[62]](https://github.com/PowerShellEmpire/Empire) |
| [S0343](/software/S0343) | [Exaramel for Windows](/software/S0343) | The [Exaramel for Windows](/software/S0343) dropper creates and starts a Windows service named wsmprovav with the description "Windows Check AV."[[63]](https://www.welivesecurity.com/2018/10/11/new-telebots-backdoor-linking-industroyer-notpetya/) |
| [S0181](/software/S0181) | [FALLCHILL](/software/S0181) | [FALLCHILL](/software/S0181) has been installed as a Windows service.[[11]](https://us-cert.cisa.gov/ncas/alerts/aa21-048a) |
| [G0046](/groups/G0046) | [FIN7](/groups/G0046) | [FIN7](/groups/G0046) created new Windows services and added them to the startup directories for persistence.[[64]](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html) |
| [S0182](/software/S0182) | [FinFisher](/software/S0182) | [FinFisher](/software/S0182) creates a new Windows service with the malicious executable for persistence.[[65]](https://web.archive.org/web/20171222050934/http://www.finfisher.com/FinFisher/index.html)[[66]](https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/) |
| [S1044](/software/S1044) | [FunnyDream](/software/S1044) | [FunnyDream](/software/S1044) has established persistence by running `sc.exe` and by setting the `WSearch` service to run automatically.[[67]](https://www.bitdefender.com/files/News/CaseStudies/study/379/Bitdefender-Whitepaper-Chinese-APT.pdf) |
| [S0666](/software/S0666) | [Gelsemium](/software/S0666) | [Gelsemium](/software/S0666) can drop itself in `C:\Windows\System32\spool\prtprocs\x64\winprint.dll` as an alternative Print Processor to be loaded automatically when the spoolsv Windows service starts.[[68]](https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf) |
| [S0032](/software/S0032) | [gh0st RAT](/software/S0032) | [gh0st RAT](/software/S0032) can create a new service to establish persistence.[[69]](https://research.nccgroup.com/2018/04/17/decoding-network-data-from-a-gh0st-rat-variant/)[[70]](https://cybersecurity.att.com/blogs/labs-research/the-odd-case-of-a-gh0strat-variant) |
| [S0493](/software/S0493) | [GoldenSpy](/software/S0493) | [GoldenSpy](/software/S0493) has established persistence by running in the background as an autostart service.[[71]](https://www.trustwave.com/en-us/resources/library/documents/the-golden-tax-department-and-the-emergence-of-goldenspy-malware/) |
| [S0342](/software/S0342) | [GreyEnergy](/software/S0342) | [GreyEnergy](/software/S0342) chooses a service, drops a DLL file, and writes it to that serviceDLL Registry key.[[72]](https://www.welivesecurity.com/wp-content/uploads/2018/10/ESET_GreyEnergy.pdf) |
| [S1211](/software/S1211) | [Hannotog](/software/S1211) | [Hannotog](/software/S1211) creates a new service for persistence.[[73]](https://www.security.com/threat-intelligence/espionage-asia-governments-cert-authority) |
| [S0071](/software/S0071) | [hcdLoader](/software/S0071) | [hcdLoader](/software/S0071) installs itself as a service for persistence.[[74]](http://www.secureworks.com/resources/blog/where-you-at-indicators-of-lateral-movement-using-at-exe-on-windows-7-systems/)[[75]](https://www.threatstream.com/blog/evasive-maneuvers-the-wekby-group-attempts-to-evade-analysis-via-custom-rop) |
| [S0697](/software/S0697) | [HermeticWiper](/software/S0697) | [HermeticWiper](/software/S0697) can load drivers by creating a new service using the `CreateServiceW` API.[[3]](https://www.crowdstrike.com/blog/how-crowdstrike-falcon-protects-against-wiper-malware-used-in-ukraine-attacks/) |
| [S0203](/software/S0203) | [Hydraq](/software/S0203) | [Hydraq](/software/S0203) creates new services to establish persistence.[[76]](https://www.symantec.com/connect/blogs/trojanhydraq-incident)[[77]](https://www.symantec.com/security_response/writeup.jsp?docid=2010-011114-1830-99)[[78]](https://www.symantec.com/connect/blogs/how-trojanhydraq-stays-your-computer) |
| [S0604](/software/S0604) | [Industroyer](/software/S0604) | [Industroyer](/software/S0604) can use an arbitrary system service to load at system boot for persistence and replaces the ImagePath registry value of a Windows service with a new backdoor binary.[[8]](https://dragos.com/blog/crashoverride/CrashOverride-01.pdf) |
| [S0259](/software/S0259) | [InnaputRAT](/software/S0259) | Some [InnaputRAT](/software/S0259) variants create a new Windows service to establish persistence.[[79]](https://asert.arbornetworks.com/innaput-actors-utilize-remote-access-trojan-since-2016-presumably-targeting-victim-files/) |
| [S0260](/software/S0260) | [InvisiMole](/software/S0260) | [InvisiMole](/software/S0260) can register a Windows service named CsPower as part of its execution chain, and a Windows service named clr\_optimization\_v2.0.51527\_X86 to achieve persistence.[[5]](https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf) |
| [S0044](/software/S0044) | [JHUHUGIT](/software/S0044) | [JHUHUGIT](/software/S0044) has registered itself as a service to establish persistence.[[80]](http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part1.pdf) |
| [S0265](/software/S0265) | [Kazuar](/software/S0265) | [Kazuar](/software/S0265) can install itself as a new service.[[81]](https://researchcenter.paloaltonetworks.com/2017/05/unit42-kazuar-multiplatform-espionage-backdoor-api-access/) |
| [G0004](/groups/G0004) | [Ke3chang](/groups/G0004) | [Ke3chang](/groups/G0004) backdoor RoyalDNS established persistence through adding a service called `Nwsapagent`.[[82]](https://research.nccgroup.com/2018/03/10/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/) |
| [S0387](/software/S0387) | [KeyBoy](/software/S0387) | [KeyBoy](/software/S0387) installs a service pointing to a malicious DLL dropped to disk.[[83]](https://blog.rapid7.com/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india/) |
| [G0094](/groups/G0094) | [Kimsuky](/groups/G0094) | [Kimsuky](/groups/G0094) has created new services for persistence.[[84]](https://securelist.com/the-kimsuky-operation-a-north-korean-apt/57915/)[[85]](https://us-cert.cisa.gov/ncas/alerts/aa20-301a) |
| [S0356](/software/S0356) | [KONNI](/software/S0356) | [KONNI](/software/S0356) has registered itself as a service using its export function.[[86]](https://blog.malwarebytes.com/threat-intelligence/2021/08/new-variant-of-konni-malware-used-in-campaign-targetting-russia/) |
| [S0236](/software/S0236) | [Kwampirs](/software/S0236) | [Kwampirs](/software/S0236) creates a new service named WmiApSrvEx to establish persistence.[[87]](https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia) |
| [G0032](/groups/G0032) | [Lazarus Group](/groups/G0032) | Several [Lazarus Group](/groups/G0032) malware families install themselves as new services.[[88]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[89]](https://web.archive.org/web/20160303200515/https:/operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf) |
| [S1202](/software/S1202) | [LockBit 3.0](/software/S1202) | [LockBit 3.0](/software/S1202) can install system services for persistence.[[90]](https://www.sentinelone.com/labs/lockbit-3-0-update-unpicking-the-ransomwares-latest-anti-analysis-and-evasion-techniques) |
| [G0030](/groups/G0030) | [Lotus Blossom](/groups/G0030) | [Lotus Blossom](/groups/G0030) has configured tools such as [Sagerunex](/software/S1210) to run as Windows services.[[91]](https://blog.talosintelligence.com/lotus-blossom-espionage-group/) |
| [S0451](/software/S0451) | [LoudMiner](/software/S0451) | [LoudMiner](/software/S0451) can automatically launch a Linux virtual machine as a service at startup if the AutoStart option is enabled in the VBoxVmService configuration file.[[92]](https://www.welivesecurity.com/2019/06/20/loudminer-mining-cracked-vst-software/) |
| [G1051](/groups/G1051) | [Medusa Group](/groups/G1051) | [Medusa Group](/groups/G1051) has used vulnerable or signed drivers to modify security solutions on victim devices.[[93]](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| [S1244](/software/S1244) | [Medusa Ransomware](/software/S1244) | [Medusa Ransomware](/software/S1244) has created a new PowerShell process using the `CreateProcessA` API.[[94]](https://securityscorecard.com/wp-content/uploads/2024/01/deep-dive-into-medusa-ransomware.pdf) |
| [S0149](/software/S0149) | [MoonWind](/software/S0149) | [MoonWind](/software/S0149) installs itself as a new service with automatic startup to establish persistence. The service checks every 60 seconds to determine if the malware is running; if not, it will spawn a new instance.[[95]](http://researchcenter.paloaltonetworks.com/2017/03/unit42-trochilus-rat-new-moonwind-rat-used-attack-thai-utility-organizations/) |
| [S0205](/software/S0205) | [Naid](/software/S0205) | [Naid](/software/S0205) creates a new service to establish.[[96]](https://www.symantec.com/security_response/writeup.jsp?docid=2012-061518-4639-99) |
| [S0630](/software/S0630) | [Nebulae](/software/S0630) | [Nebulae](/software/S0630) can create a service to establish persistence.[[97]](https://www.bitdefender.com/files/News/CaseStudies/study/396/Bitdefender-PR-Whitepaper-NAIKON-creat5397-en-EN.pdf) |
| [S0210](/software/S0210) | [Nerex](/software/S0210) | [Nerex](/software/S0210) creates a Registry subkey that registers a new service.[[98]](https://www.symantec.com/security_response/writeup.jsp?docid=2012-051515-3445-99) |
| [S0118](/software/S0118) | [Nidiran](/software/S0118) | [Nidiran](/software/S0118) can create a new service named msamger (Microsoft Security Accounts Manager).[[99]](https://www.symantec.com/security_response/writeup.jsp?docid=2015-120123-5521-99) |
| [S1090](/software/S1090) | [NightClub](/software/S1090) | [NightClub](/software/S1090) has created a Windows service named `WmdmPmSp` to establish persistence.[[100]](https://www.welivesecurity.com/en/eset-research/moustachedbouncer-espionage-against-foreign-diplomats-in-belarus/) |
| [S1100](/software/S1100) | [Ninja](/software/S1100) | [Ninja](/software/S1100) can create the services `httpsvc` and `w3esvc` for persistence .[[101]](https://securelist.com/toddycat/106799/) |
| [G0049](/groups/G0049) | [OilRig](/groups/G0049) | [OilRig](/groups/G0049) has used a compromised Domain Controller to create a service on a remote host.[[102]](https://www.security.com/threat-intelligence/crambus-middle-east-government) |
| [S0439](/software/S0439) | [Okrum](/software/S0439) | To establish persistence, [Okrum](/software/S0439) can install itself as a new service named NtmSsvc.[[103]](https://www.welivesecurity.com/wp-content/uploads/2019/07/ESET_Okrum_and_Ketrican.pdf) |
| [C0012](/campaigns/C0012) | [Operation CuckooBees](/campaigns/C0012) | During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors modified the `IKEEXT` and `PrintNotify` Windows services for persistence.[[104]](https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques) |
| [C0061](/campaigns/C0061) | [Operation Digital Eye](/campaigns/C0061) | During [Operation Digital Eye](https://attack.mitre.org/campaigns/C0061), threat actors created a service named Visual Studio Code Service to run Visual Studio code.[[105]](https://www.sentinelone.com/labs/operation-digital-eye-chinese-apt-compromises-critical-digital-infrastructure-via-visual-studio-code-tunnels/) |
| [C0006](/campaigns/C0006) | [Operation Honeybee](/campaigns/C0006) | During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), threat actors installed DLLs and backdoors as Windows services.[[106]](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-uncovers-operation-honeybee-malicious-document-campaign-targeting-humanitarian-aid-groups/) |
| [S0664](/software/S0664) | [Pandora](/software/S0664) | [Pandora](/software/S0664) has the ability to gain system privileges through Windows services.[[107]](https://www.trendmicro.com/en_us/research/21/d/iron-tiger-apt-updates-toolkit-with-evolved-sysupdate-malware-va.html) |
| [S1031](/software/S1031) | [PingPull](/software/S1031) | [PingPull](/software/S1031) has the ability to install itself as a service.[[108]](https://unit42.paloaltonetworks.com/pingpull-gallium/) |
| [S0501](/software/S0501) | [PipeMon](/software/S0501) | [PipeMon](/software/S0501) can establish persistence by registering a malicious DLL as an alternative Print Processor which is loaded when the print spooler service starts.[[109]](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/) |
| [S0013](/software/S0013) | [PlugX](/software/S0013) | [PlugX](/software/S0013) can be added as a service to establish persistence. [PlugX](/software/S0013) also has a module to change service configurations as well as start, control, and delete services.[[110]](http://circl.lu/assets/files/tr-12/tr-12-circl-plugx-analysis-v1.pdf)[[111]](https://lastline3.rssing.com/chan-29044929/all_p1.html#c29044929a2)[[112]](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)[[113]](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)[[114]](https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx) |
| [S0012](/software/S0012) | [PoisonIvy](/software/S0012) | [PoisonIvy](/software/S0012) creates a Registry subkey that registers a new service. [PoisonIvy](/software/S0012) also creates a Registry entry modifying the Logical Disk Manager service to point to a malicious DLL dropped to disk.[[115]](https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99) |
| [S0194](/software/S0194) | [PowerSploit](/software/S0194) | [PowerSploit](/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and replace/modify service binaries, paths, and configs.[[116]](https://github.com/PowerShellMafia/PowerSploit)[[117]](http://powersploit.readthedocs.io) |
| [G0056](/groups/G0056) | [PROMETHIUM](/groups/G0056) | [PROMETHIUM](/groups/G0056) has created new services and modified existing services for persistence.[[118]](https://www.bitdefender.com/files/News/CaseStudies/study/353/Bitdefender-Whitepaper-StrongPity-APT.pdf) |
| [S0029](/software/S0029) | [PsExec](/software/S0029) | [PsExec](/software/S0029) can leverage Windows services to escalate privileges from administrator to SYSTEM with the `-s` argument.[[119]](https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx) |
| [S0650](/software/S0650) | [QakBot](/software/S0650) | [QakBot](/software/S0650) can remotely create a temporary service on a target host.[[120]](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/) |
| [S0481](/software/S0481) | [Ragnar Locker](/software/S0481) | [Ragnar Locker](/software/S0481) has used sc.exe to create a new service for the VirtualBox driver.[[121]](https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/) |
| [S0629](/software/S0629) | [RainyDay](/software/S0629) | [RainyDay](/software/S0629) can use services to establish persistence.[[97]](https://www.bitdefender.com/files/News/CaseStudies/study/396/Bitdefender-PR-Whitepaper-NAIKON-creat5397-en-EN.pdf) |
| [S0169](/software/S0169) | [RawPOS](/software/S0169) | [RawPOS](/software/S0169) installs itself as a service to maintain persistence.[[122]](https://www.kroll.com/en/insights/publications/malware-analysis-report-rawpos-malware)[[123]](http://sjc1-te-ftp.trendmicro.com/images/tex/pdf/RawPOS%20Technical%20Brief.pdf)[[124]](https://www.youtube.com/watch?v=fevGZs0EQu8) |
| [S0495](/software/S0495) | [RDAT](/software/S0495) | [RDAT](/software/S0495) has created a service when it is installed on the victim machine.[[125]](https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/) |
| [S0172](/software/S0172) | [Reaver](/software/S0172) | [Reaver](/software/S0172) installs itself as a new service.[[126]](https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/) |
| [S0332](/software/S0332) | [Remcos](/software/S0332) | [Remcos](/software/S0332) can terminate, suspend, and resume a process by PID.[[127]](https://www.fortinet.com/blog/threat-research/new-campaign-uses-remcos-rat-to-exploit-victims) |
| [S0074](/software/S0074) | [Sakula](/software/S0074) | Some [Sakula](/software/S0074) samples install themselves as services for persistence by calling WinExec with the `net start` argument.[[128]](http://www.secureworks.com/cyber-threat-intelligence/threats/sakula-malware-family/) |
| [S1099](/software/S1099) | [Samurai](/software/S1099) | [Samurai](/software/S1099) can create a service at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost` to trigger execution and maintain persistence.[[101]](https://securelist.com/toddycat/106799/) |
| [S0345](/software/S0345) | [Seasalt](/software/S0345) | [Seasalt](/software/S0345) is capable of installing itself as a service.[[129]](https://www.mandiant.com/sites/default/files/2021-09/mandiant-apt1-report.pdf) |
| [S0140](/software/S0140) | [Shamoon](/software/S0140) | [Shamoon](/software/S0140) creates a new service named "ntssrv" to execute the payload. Newer versions create the "MaintenaceSrv" and "hdv\_725x" services.[[130]](http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/)[[131]](https://unit42.paloaltonetworks.com/shamoon-3-targets-oil-gas-organization/) |
| [S0444](/software/S0444) | [ShimRat](/software/S0444) | [ShimRat](/software/S0444) has installed a Windows service to maintain persistence on victim machines.[[132]](https://foxitsecurity.files.wordpress.com/2016/06/fox-it_mofang_threatreport_tlp-white.pdf) |
| [S0692](/software/S0692) | [SILENTTRINITY](/software/S0692) | [SILENTTRINITY](/software/S0692) can establish persistence by creating a new service.[[133]](https://github.com/byt3bl33d3r/SILENTTRINITY/tree/master/silenttrinity/core/teamserver/modules/boo) |
| [S0533](/software/S0533) | [SLOTHFULMEDIA](/software/S0533) | [SLOTHFULMEDIA](/software/S0533) has created a service on victim machines named "TaskFrame" to establish persistence.[[134]](https://us-cert.cisa.gov/ncas/analysis-reports/ar20-275a) |
| [S1232](/software/S1232) | [SplatDropper](/software/S1232) | [SplatDropper](/software/S1232) has created a service to execute a payload.[[46]](https://www.zscaler.com/blogs/security-research/latest-mustang-panda-arsenal-paklog-corklog-and-splatcloak-p2) |
| [S1037](/software/S1037) | [STARWHALE](/software/S1037) | [STARWHALE](/software/S1037) has the ability to create the following Windows service to establish persistence on an infected host: `sc create Windowscarpstss binpath= "cmd.exe /c cscript.exe c:\\windows\\system32\\w7_1.wsf humpback_whale" start= "auto" obj= "LocalSystem"`.[[135]](https://www.mandiant.com/resources/telegram-malware-iranian-espionage) |
| [S0142](/software/S0142) | [StreamEx](/software/S0142) | [StreamEx](/software/S0142) establishes persistence by installing a new service pointing to its DLL and setting the service to auto-start.[[136]](https://www.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar) |
| [S0491](/software/S0491) | [StrongPity](/software/S0491) | [StrongPity](/software/S0491) has created new services and modified existing services for persistence.[[137]](https://blog.talosintelligence.com/2020/06/promethium-extends-with-strongpity3.html) |
| [S0603](/software/S0603) | [Stuxnet](/software/S0603) | [Stuxnet](/software/S0603) uses a driver registered as a boot start service as the main load-point.[[138]](https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier-11-en) |
| [S1049](/software/S1049) | [SUGARUSH](/software/S1049) | [SUGARUSH](/software/S1049) has created a service named `Service1` for persistence.[[139]](https://www.mandiant.com/resources/blog/suspected-iranian-actor-targeting-israeli-shipping) |
| [S0663](/software/S0663) | [SysUpdate](/software/S0663) | [SysUpdate](/software/S0663) can create a service to establish persistence.[[107]](https://www.trendmicro.com/en_us/research/21/d/iron-tiger-apt-updates-toolkit-with-evolved-sysupdate-malware-va.html) |
| [S0164](/software/S0164) | [TDTESS](/software/S0164) | If running as administrator, [TDTESS](/software/S0164) installs itself as a new service named bmwappushservice to establish persistence.[[140]](http://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf) |
| [G0139](/groups/G0139) | [TeamTNT](/groups/G0139) | [TeamTNT](/groups/G0139) has used malware that adds cryptocurrency miners as a service.[[141]](https://cybersecurity.att.com/blogs/labs-research/teamtnt-with-new-campaign-aka-chimaera) |
| [S0560](/software/S0560) | [TEARDROP](/software/S0560) | [TEARDROP](/software/S0560) ran as a Windows service from the `c:\windows\syswow64` folder.[[142]](https://research.checkpoint.com/2020/sunburst-teardrop-and-the-netsec-new-normal/)[[143]](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html) |
| [G0027](/groups/G0027) | [Threat Group-3390](/groups/G0027) | [Threat Group-3390](/groups/G0027)'s malware can create a new service, sometimes naming it after the config information, to gain persistence.[[144]](https://research.nccgroup.com/2018/05/18/emissary-panda-a-potential-new-malicious-tool/)[[145]](https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html) |
| [S0665](/software/S0665) | [ThreatNeedle](/software/S0665) | [ThreatNeedle](/software/S0665) can run in memory and register its payload as a Windows service.[[146]](https://securelist.com/lazarus-threatneedle/100803/) |
| [S0004](/software/S0004) | [TinyZBot](/software/S0004) | [TinyZBot](/software/S0004) can install as a Windows service for persistence.[[147]](https://web.archive.org/web/20200302085133/https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf) |
| [S1239](/software/S1239) | [TONESHELL](/software/S1239) | [TONESHELL](/software/S1239) has created a malicious service DISMsrv to maintain persistence.[[148]](https://unit42.paloaltonetworks.com/stately-taurus-attacks-se-asian-government/) |
| [S0266](/software/S0266) | [TrickBot](/software/S0266) | [TrickBot](/software/S0266) establishes persistence by creating an autostart service that allows it to run whenever the machine boots.[[149]](https://blog.trendmicro.com/trendlabs-security-intelligence/trickbot-shows-off-new-trick-password-grabber-module/) |
| [G0081](/groups/G0081) | [Tropic Trooper](/groups/G0081) | [Tropic Trooper](/groups/G0081) has installed a service pointing to a malicious DLL dropped to disk.[[150]](https://web.archive.org/web/20211129064701/https://www.pwc.co.uk/issues/cyber-security-services/research/the-keyboys-are-back-in-town.html) |
| [S0263](/software/S0263) | [TYPEFRAME](/software/S0263) | [TYPEFRAME](/software/S0263) variants can add malicious DLL modules as new services.[TYPEFRAME](/software/S0263) can also delete services from the victim’s machine.[[151]](https://www.us-cert.gov/ncas/analysis-reports/AR18-165A) |
| [S0022](/software/S0022) | [Uroburos](/software/S0022) | [Uroburos](/software/S0022) has registered a service, typically named `WerFaultSvc`, to decrypt and find a kernel driver and kernel driver loader to maintain persistence.[[152]](https://www.cisa.gov/sites/default/files/2023-05/aa23-129a_snake_malware_2.pdf) |
| [S0386](/software/S0386) | [Ursnif](/software/S0386) | [Ursnif](/software/S0386) has registered itself as a system service in the Registry for automatic execution at system startup.[[153]](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/PE_URSNIF.A2?_ga=2.131425807.1462021705.1559742358-1202584019.1549394279) |
| [S0180](/software/S0180) | [Volgmer](/software/S0180) | [Volgmer](/software/S0180) installs a copy of itself in a randomly selected service, then overwrites the ServiceDLL entry in the service's Registry entry. Some [Volgmer](/software/S0180) variants also install .dll files as services with names generated by a list of hard-coded strings.[[154]](https://www.us-cert.gov/ncas/alerts/TA17-318B)[[155]](https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-D_WHITE_S508C.PDF)[[156]](https://web.archive.org/web/20181126143456/https://www.symantec.com/security-center/writeup/2014-081811-3237-99?tabid=2) |
| [S0366](/software/S0366) | [WannaCry](/software/S0366) | [WannaCry](/software/S0366) creates the service "mssecsvc2.0" with the display name "Microsoft Security Center (2.0) Service."[[157]](https://web.archive.org/web/20230522041200/https://logrhythm.com/blog/a-technical-analysis-of-wannacry-ransomware/)[[158]](https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html) |
| [S0612](/software/S0612) | [WastedLocker](/software/S0612) | [WastedLocker](/software/S0612) created and established a service that runs until the encryption process is complete.[[159]](https://research.nccgroup.com/2020/06/23/wastedlocker-a-new-ransomware-variant-developed-by-the-evil-corp-group/) |
| [S0206](/software/S0206) | [Wiarp](/software/S0206) | [Wiarp](/software/S0206) creates a backdoor through which remote attackers can create a service.[[160]](https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99) |
| [S0176](/software/S0176) | [Wingbird](/software/S0176) | [Wingbird](/software/S0176) uses services.exe to register a new autostart service named "Audit Service" using a copy of the local lsass.exe file.[[161]](http://download.microsoft.com/download/E/B/0/EB0F50CC-989C-4B66-B7F6-68CD3DC90DE3/Microsoft_Security_Intelligence_Report_Volume_21_English.pdf)[[162]](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/Wingbird.A!dha) |
| [S0141](/software/S0141) | [Winnti for Windows](/software/S0141) | [Winnti for Windows](/software/S0141) sets its DLL file as a new service in the Registry to establish persistence.[[163]](https://blogs.technet.microsoft.com/mmpc/2017/01/25/detecting-threat-actors-in-recent-german-industrial-attacks-with-windows-defender-atp/) |
| [G0102](/groups/G0102) | [Wizard Spider](/groups/G0102) | [Wizard Spider](/groups/G0102) has installed [TrickBot](/software/S0266) as a service named ControlServiceA in order to establish persistence.[[164]](https://www.crowdstrike.com/blog/timelining-grim-spiders-big-game-hunting-tactics/)[[165]](https://web.archive.org/web/20220313061955/https://www.mandiant.com/sites/default/files/2021-10/fin12-group-profile.pdf) |
| [S0230](/software/S0230) | [ZeroT](/software/S0230) | [ZeroT](/software/S0230) can add a new service to ensure [PlugX](/software/S0013) persists on the system when delivered as another payload onto the system.[[114]](https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx) |
| [S0086](/software/S0086) | [ZLib](/software/S0086) | [ZLib](/software/S0086) creates Registry keys to allow itself to run as various services.[[166]](https://s7d2.scene7.com/is/content/cylance/prod/cylance-web/en-us/resources/knowledge-center/resource-library/reports/Op_Dust_Storm_Report.pdf) |
| [S0350](/software/S0350) | [zwShell](/software/S0350) | [zwShell](/software/S0350) has established persistence by adding itself as a new service.[[167]](https://scadahacker.com/library/Documents/Cyber_Events/McAfee%20-%20Night%20Dragon%20-%20Global%20Energy%20Cyberattacks.pdf) |
| [S0412](/software/S0412) | [ZxShell](/software/S0412) | [ZxShell](/software/S0412) can create a new service using the service parser function ProcessScCommand.[[168]](https://blogs.cisco.com/security/talos/opening-zxshell) |

Mitigations
-----------

| ID | Mitigation | Description |
| --- | --- | --- |
| [M1047](/mitigations/M1047) | [Audit](/mitigations/M1047) | Use auditing tools capable of detecting privilege and service abuse opportunities on systems within an enterprise and correct them. |
| [M1040](/mitigations/M1040) | [Behavior Prevention on Endpoint](/mitigations/M1040) | On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent an application from writing a signed vulnerable driver to the system.[[169]](https://www.microsoft.com/security/blog/2021/12/08/improve-kernel-security-with-the-new-microsoft-vulnerable-and-malicious-driver-reporting-center/) On Windows 10 and 11, enable Microsoft Vulnerable Driver Blocklist to assist in hardening against third party-developed service drivers.[[170]](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules) |
| [M1045](/mitigations/M1045) | [Code Signing](/mitigations/M1045) | Enforce registration and execution of only legitimately signed service drivers where possible. |
| [M1028](/mitigations/M1028) | [Operating System Configuration](/mitigations/M1028) | Ensure that Driver Signature Enforcement is enabled to restrict unsigned drivers from being installed. |
| [M1018](/mitigations/M1018) | [User Account Management](/mitigations/M1018) | Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service configurations. |

Detection Strategy
------------------

| ID | Name | Analytic ID | Analytic Description |
| --- | --- | --- | --- |
| [DET0552](/detectionstrategies/DET0552) | [Detection of Windows Service Creation or Modification](/detectionstrategies/DET0552) | [AN1527](/detectionstrategies/DET0552#AN1527) | Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary paths. Detects privilege escalation via driver installation or `CreateServiceW` usage. Correlates parent-child lineage, startup behavior, and rare service names. |

References
----------

1. [Microsoft. (n.d.). Services. Retrieved June 7, 2016.](https://technet.microsoft.com/en-us/library/cc772408.aspx)
2. [Nicolas Falliere, Liam O. Murchu, Eric Chien. (2011, February). W32.Stuxnet Dossier. Retrieved December 7, 2020.](https://www.wired.com/images_blogs/threatlevel/2010/11/w32_stuxnet_dossier.pdf)
3. [Thomas, W. et al. (2022, February 25). CrowdStrike Falcon Protects from New Wiper Malware Used in Ukraine Cyberattacks. Retrieved March 25, 2022.](https://www.crowdstrike.com/blog/how-crowdstrike-falcon-protects-against-wiper-malware-used-in-ukraine-attacks/)
4. [Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.](https://unit42.paloaltonetworks.com/acidbox-rare-malware/)
5. [Hromcova, Z. and Cherpanov, A. (2020, June). INVISIMOLE: THE HIDDEN PART OF THE STORY. Retrieved July 16, 2020.](https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf)
6. [Joshua Wright. (2020, October 13). Retrieved March 22, 2024.](https://www.sans.org/blog/red-team-tactics-hiding-windows-services/)
7. [Joshua Wright. (2020, October 14). Retrieved March 22, 2024.](https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services/)
8. [Dragos Inc.. (2017, June 13). CRASHOVERRIDE Analysis of the Threat to Electric Grid Operations. Retrieved December 18, 2020.](https://dragos.com/blog/crashoverride/CrashOverride-01.pdf)
9. [Amitai Ben & Shushan Ehrlich. (2021, May). From Wiper to Ransomware: The Evolution of Agrius. Retrieved May 21, 2024.](https://assets.sentinelone.com/sentinellabs/evol-agrius)
10. [Dahan, A. et al. (2019, December 11). DROPPING ANCHOR: FROM A TRICKBOT INFECTION TO THE DISCOVERY OF THE ANCHOR MALWARE. Retrieved September 10, 2020.](https://www.cybereason.com/blog/dropping-anchor-from-a-trickbot-infection-to-the-discovery-of-the-anchor-malware)
11. [Cybersecurity and Infrastructure Security Agency. (2021, February 21). AppleJeus: Analysis of North Korea’s Cryptocurrency Malware. Retrieved March 1, 2021.](https://us-cert.cisa.gov/ncas/alerts/aa21-048a)
12. [Grunzweig, J., Lee, B. (2016, January 22). New Attacks Linked to C0d0so0 Group. Retrieved August 2, 2018.](https://researchcenter.paloaltonetworks.com/2016/01/new-attacks-linked-to-c0d0s0-group/)
13. [Moran, N., et al. (2014, November 21). Operation Double Tap. Retrieved January 14, 2016.](https://www.fireeye.com/blog/threat-research/2014/11/operation_doubletap.html)
14. [Foltýn, T. (2018, March 13). OceanLotus ships new backdoor using old tricks. Retrieved May 22, 2018.](https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/)
15. [Dahan, A. (2017). Operation Cobalt Kitty. Retrieved December 27, 2018.](https://cdn2.hubspot.net/hubfs/3354902/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty.pdf)
16. [Dumont, R. (2019, March 20). Fake or Fake: Keeping up with OceanLotus decoys. Retrieved April 1, 2019.](https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/)
17. [DHS/CISA. (2020, August 26). FASTCash 2.0: North Korea's BeagleBoyz Robbing Banks. Retrieved September 29, 2021.](https://us-cert.cisa.gov/ncas/alerts/aa20-239a)
18. [Fraser, N., et al. (2019, August 7). Double DragonAPT41, a dual espionage and cyber crime operation APT41. Retrieved September 23, 2019.](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf)
19. [Rostovcev, N. (2021, June 10). Big airline heist APT41 likely behind a third-party attack on Air India. Retrieved August 26, 2021.](https://www.group-ib.com/blog/colunmtk-apt41/)
20. [Glyer, C, et al. (2020, March). This Is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits. Retrieved April 28, 2020.](https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html)
21. [Mike Stokkel et al. (2024, July 18). APT41 Has Arisen From the DUST. Retrieved September 16, 2024.](https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust)
22. [CrowdStrike. (2023). 2022 Falcon OverWatch Threat Hunting Report. Retrieved May 20, 2024.](https://go.crowdstrike.com/rs/281-OBQ-266/images/2022OverWatchThreatHuntingReport.pdf)
23. [Hromcova, Z. (2019, October). AT COMMANDS, TOR-BASED COMMUNICATIONS: MEET ATTOR, A FANTASY CREATURE AND ALSO A SPY PLATFORM. Retrieved May 6, 2020.](https://www.welivesecurity.com/wp-content/uploads/2019/10/ESET_Attor.pdf)
24. [Trend Micro. (2018, November 20). Lazarus Continues Heists, Mounts Attacks on Financial Organizations in Latin America. Retrieved December 3, 2018.](https://blog.trendmicro.com/trendlabs-security-intelligence/lazarus-continues-heists-mounts-attacks-on-financial-organizations-in-latin-america/)
25. [Sherstobitoff, R. (2018, March 08). Hidden Cobra Targets Turkish Financial Sector With New Bankshot Implant. Retrieved May 18, 2018.](https://securingtomorrow.mcafee.com/mcafee-labs/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant/)
26. [US-CERT. (2017, December 13). Malware Analysis Report (MAR) - 10135536-B. Retrieved July 17, 2018.](https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-B_WHITE.PDF)
27. [Lee, B. Grunzweig, J. (2015, December 22). BBSRAT Attacks Targeting Russian Organizations Linked to Roaming Tiger. Retrieved August 19, 2016.](http://researchcenter.paloaltonetworks.com/2015/12/bbsrat-attacks-targeting-russian-organizations-linked-to-roaming-tiger/)
28. [Mercer, W., et al. (2020, March 5). Bisonal: 10 years of play. Retrieved January 26, 2022.](https://blog.talosintelligence.com/2020/03/bisonal-10-years-of-play.html)
29. [Frankoff, S., Hartley, B. (2018, November 14). Big Game Hunting: The Evolution of INDRIK SPIDER From Dridex Wire Fraud to BitPaymer Targeted Ransomware. Retrieved January 6, 2021.](https://www.crowdstrike.com/blog/big-game-hunting-the-evolution-of-indrik-spider-from-dridex-wire-fraud-to-bitpaymer-targeted-ransomware/)
30. [Zargarov, N. (2022, May 2). New Black Basta Ransomware Hijacks Windows Fax Service. Retrieved March 7, 2023.](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/)
31. [Avertium. (2022, June 1). AN IN-DEPTH LOOK AT BLACK BASTA RANSOMWARE. Retrieved March 7, 2023.](https://www.avertium.com/resources/threat-reports/in-depth-look-at-black-basta-ransomware)
32. [Symantec Threat Hunter Team. (2022, October 21). Exbyte: BlackByte Ransomware Attackers Deploy New Exfiltration Tool. Retrieved December 16, 2024.](https://www.security.com/threat-intelligence/blackbyte-exbyte-ransomware)
33. [Microsoft Incident Response. (2023, July 6). The five-day job: A BlackByte ransomware intrusion case study. Retrieved December 16, 2024.](https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/)
34. [F-Secure Labs. (2014). BlackEnergy & Quedagh: The convergence of crimeware and APT attacks. Retrieved March 24, 2016.](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf)
35. [Lambert, T. (2020, May 7). Introducing Blue Mockingbird. Retrieved May 26, 2020.](https://redcanary.com/blog/blue-mockingbird-cryptominer/)
36. [Robert Falcone, Mike Scott, Juan Cortes. (2015, November 10). Bookworm Trojan: A Model of Modular Architecture. Retrieved July 21, 2025.](https://unit42.paloaltonetworks.com/bookworm-trojan-a-model-of-modular-architecture/)
37. [Ladley, F. (2012, May 15). Backdoor.Briba. Retrieved February 21, 2018.](https://www.symantec.com/security_response/writeup.jsp?docid=2012-051515-2843-99)
38. [Kaspersky Lab's Global Research and Analysis Team. (2015, February). CARBANAK APT THE GREAT BANK ROBBERY. Retrieved August 23, 2018.](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)
39. [ESET. (2017, March 30). Carbon Paper: Peering into Turla’s second stage backdoor. Retrieved November 7, 2018.](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)
40. [Balanza, M. (2018, April 02). Infostealer.Catchamas. Retrieved November 17, 2024.](https://web.archive.org/web/20190508165711/https://www-west.symantec.com/content/symantec/english/en/security-center/writeup.html/2018-040209-1742-99)
41. [Biderman, O. et al. (2022, October 3). REVEALING EMPEROR DRAGONFLY: NIGHT SKY AND CHEERSCRYPT - A SINGLE RANSOMWARE GROUP. Retrieved December 6, 2023.](https://blog.sygnia.co/revealing-emperor-dragonfly-a-chinese-ransomware-group)
42. [Chen, T. and Chen, Z. (2020, February 17). CLAMBLING - A New Backdoor Base On Dropbox. Retrieved November 12, 2021.](https://www.talent-jump.com/article/2020/02/17/CLAMBLING-A-New-Backdoor-Base-On-Dropbox-en/)
43. [Matveeva, V. (2017, August 15). Secrets of Cobalt. Retrieved October 10, 2018.](https://www.group-ib.com/blog/cobalt)
44. [Cobalt Strike. (2017, December 8). Tactics, Techniques, and Procedures. Retrieved November 17, 2024.](https://web.archive.org/web/20210924171429/https://www.cobaltstrike.com/downloads/reports/tacticstechniquesandprocedures.pdf)
45. [Burton, K. (n.d.). The Conficker Worm. Retrieved February 18, 2021.](https://web.archive.org/web/20200125132645/https://www.sans.org/security-resources/malwarefaq/conficker-worm)
46. [Sudeep Singh. (2025, April 16). Latest Mustang Panda Arsenal: PAKLOG, CorKLOG, and SplatCloak | P2. Retrieved September 12, 2025.](https://www.zscaler.com/blogs/security-research/latest-mustang-panda-arsenal-paklog-corklog-and-splatcloak-p2)
47. [F-Secure Labs. (2014, July). COSMICDUKE Cosmu with a twist of MiniDuke. Retrieved July 3, 2014.](https://blog.f-secure.com/wp-content/uploads/2019/10/CosmicDuke.pdf)
48. [F-Secure Labs. (2015, April 22). CozyDuke: Malware Analysis. Retrieved December 10, 2015.](https://www.f-secure.com/documents/996508/1030745/CozyDuke)
49. [Roccio, T., et al. (2021, April). Technical Analysis of Cuba Ransomware. Retrieved June 18, 2021.](https://www.mcafee.com/enterprise/en-us/assets/reports/rp-cuba-ransomware.pdf)
50. [Golovanov, S. (2018, December 6). DarkVishnya: Banks attacked through direct connection to local network. Retrieved May 15, 2020.](https://securelist.com/darkvishnya/89169/)
51. [Checkpoint Research. (2021, November 15). Uncovering MosesStaff techniques: Ideology over Money. Retrieved August 11, 2022.](https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/)
52. [Hod Gavriel. (2019, November 21). Dtrack: In-depth analysis of APT on a nuclear power plant. Retrieved January 20, 2021.](https://www.cyberbit.com/blog/endpoint-security/dtrack-apt-malware-found-in-nuclear-power-plant/)
53. [Symantec Security Response. (2011, November). W32.Duqu: The precursor to the next Stuxnet. Retrieved September 17, 2015.](https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/w32_duqu_the_precursor_to_the_next_stuxnet.pdf)
54. [Symantec Security Response. (2015, June 23). Dyre: Emerging threat on financial fraud landscape. Retrieved August 23, 2018.](http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/dyre-emerging-threat.pdf)
55. [Chen, J., et al. (2022). Delving Deep: An Analysis of Earth Lusca’s Operations. Retrieved July 1, 2022.](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf)
56. [Falcone, R., et al.. (2015, June 16). Operation Lotus Blossom. Retrieved February 15, 2016.](https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html)
57. [Jan Holman, Tomas Zvara. (2024, October 23). Embargo ransomware: Rock’n’Rust. Retrieved October 19, 2025.](https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/)
58. [Falcone, R. and Miller-Osborn, J. (2016, February 3). Emissary Trojan Changelog: Did Operation Lotus Blossom Cause It to Evolve?. Retrieved February 15, 2016.](http://researchcenter.paloaltonetworks.com/2016/02/emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve/)
59. [US-CERT. (2018, July 20). Alert (TA18-201A) Emotet Malware. Retrieved March 25, 2019.](https://www.us-cert.gov/ncas/alerts/TA18-201A)
60. [Mclellan, M.. (2018, November 19). Lazy Passwords Become Rocket Fuel for Emotet SMB Spreader. Retrieved March 25, 2019.](https://www.secureworks.com/blog/lazy-passwords-become-rocket-fuel-for-emotet-smb-spreader)
61. [Binary Defense. (n.d.). Emotet Evolves With new Wi-Fi Spreader. Retrieved September 8, 2023.](https://www.binarydefense.com/resources/blog/emotet-evolves-with-new-wi-fi-spreader/)
62. [Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.](https://github.com/PowerShellEmpire/Empire)
63. [Cherepanov, A., Lipovsky, R. (2018, October 11). New TeleBots backdoor: First evidence linking Industroyer to NotPetya. Retrieved November 27, 2018.](https://www.welivesecurity.com/2018/10/11/new-telebots-backdoor-linking-industroyer-notpetya/)
64. [Carr, N., et al. (2018, August 01). On the Hunt for FIN7: Pursuing an Enigmatic and Evasive Global Criminal Operation. Retrieved August 23, 2018.](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)
65. [FinFisher. (n.d.). Retrieved September 12, 2024.](https://web.archive.org/web/20171222050934/http://www.finfisher.com/FinFisher/index.html)
66. [Allievi, A.,Flori, E. (2018, March 01). FinFisher exposed: A researcher’s tale of defeating traps, tricks, and complex virtual machines. Retrieved July 9, 2018.](https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/)
67. [Vrabie, V. (2020, November). Dissecting a Chinese APT Targeting South Eastern Asian Government Institutions. Retrieved September 19, 2022.](https://www.bitdefender.com/files/News/CaseStudies/study/379/Bitdefender-Whitepaper-Chinese-APT.pdf)
68. [Dupuy, T. and Faou, M. (2021, June). Gelsemium. Retrieved November 30, 2021.](https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf)
69. [Pantazopoulos, N. (2018, April 17). Decoding network data from a Gh0st RAT variant. Retrieved November 2, 2018.](https://research.nccgroup.com/2018/04/17/decoding-network-data-from-a-gh0st-rat-variant/)
70. [Quinn, J. (2019, March 25). The odd case of a Gh0stRAT variant. Retrieved July 15, 2020.](https://cybersecurity.att.com/blogs/labs-research/the-odd-case-of-a-gh0strat-variant)
71. [Trustwave SpiderLabs. (2020, June 25). The Golden Tax Department and Emergence of GoldenSpy Malware. Retrieved July 23, 2020.](https://www.trustwave.com/en-us/resources/library/documents/the-golden-tax-department-and-the-emergence-of-goldenspy-malware/)
72. [Cherepanov, A. (2018, October). GREYENERGY A successor to BlackEnergy. Retrieved November 15, 2018.](https://www.welivesecurity.com/wp-content/uploads/2018/10/ESET_GreyEnergy.pdf)
73. [Symntec Threat Hunter Team. (2022, November 12). Billbug: State-sponsored Actor Targets Cert Authority, Government Agencies in Multiple Asian Countries. Retrieved March 15, 2025.](https://www.security.com/threat-intelligence/espionage-asia-governments-cert-authority)
74. [Carvey, H.. (2014, September 2). Where you AT?: Indicators of lateral movement using at.exe on Windows 7 systems. Retrieved January 25, 2016.](http://www.secureworks.com/resources/blog/where-you-at-indicators-of-lateral-movement-using-at-exe-on-windows-7-systems/)
75. [Shelmire, A.. (2015, July 6). Evasive Maneuvers. Retrieved January 22, 2016.](https://www.threatstream.com/blog/evasive-maneuvers-the-wekby-group-attempts-to-evade-analysis-via-custom-rop)
76. [Symantec Security Response. (2010, January 18). The Trojan.Hydraq Incident. Retrieved February 20, 2018.](https://www.symantec.com/connect/blogs/trojanhydraq-incident)
77. [Lelli, A. (2010, January 11). Trojan.Hydraq. Retrieved February 20, 2018.](https://www.symantec.com/security_response/writeup.jsp?docid=2010-011114-1830-99)
78. [Fitzgerald, P. (2010, January 26). How Trojan.Hydraq Stays On Your Computer. Retrieved February 22, 2018.](https://www.symantec.com/connect/blogs/how-trojanhydraq-stays-your-computer)
79. [ASERT Team. (2018, April 04). Innaput Actors Utilize Remote Access Trojan Since 2016, Presumably Targeting Victim Files. Retrieved July 9, 2018.](https://asert.arbornetworks.com/innaput-actors-utilize-remote-access-trojan-since-2016-presumably-targeting-victim-files/)
80. [ESET. (2016, October). En Route with Sednit - Part 1: Approaching the Target. Retrieved November 8, 2016.](http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part1.pdf)
81. [Levene, B, et al. (2017, May 03). Kazuar: Multiplatform Espionage Backdoor with API Access. Retrieved July 17, 2018.](https://researchcenter.paloaltonetworks.com/2017/05/unit42-kazuar-multiplatform-espionage-backdoor-api-access/)
82. [Smallridge, R. (2018, March 10). APT15 is alive and strong: An analysis of RoyalCli and RoyalDNS. Retrieved April 4, 2018.](https://research.nccgroup.com/2018/03/10/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/)
83. [Guarnieri, C., Schloesser M. (2013, June 7). KeyBoy, Targeted Attacks against Vietnam and India. Retrieved June 14, 2019.](https://blog.rapid7.com/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india/)
84. [Tarakanov , D.. (2013, September 11). The “Kimsuky” Operation: A North Korean APT?. Retrieved August 13, 2019.](https://securelist.com/the-kimsuky-operation-a-north-korean-apt/57915/)
85. [CISA, FBI, CNMF. (2020, October 27). https://us-cert.cisa.gov/ncas/alerts/aa20-301a. Retrieved November 4, 2020.](https://us-cert.cisa.gov/ncas/alerts/aa20-301a)

1. [Threat Intelligence Team. (2021, August 23). New variant of Konni malware used in campaign targetting Russia. Retrieved January 5, 2022.](https://blog.malwarebytes.com/threat-intelligence/2021/08/new-variant-of-konni-malware-used-in-campaign-targetting-russia/)
2. [Symantec Security Response Attack Investigation Team. (2018, April 23). New Orangeworm attack group targets the healthcare sector in the U.S., Europe, and Asia. Retrieved May 8, 2018.](https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia)
3. [Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Unraveling the Long Thread of the Sony Attack. Retrieved February 25, 2016.](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)
4. [Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved November 17, 2024.](https://web.archive.org/web/20160303200515/https:/operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf)
5. [Walter, J. (2022, July 21). LockBit 3.0 Update | Unpicking the Ransomware’s Latest Anti-Analysis and Evasion Techniques. Retrieved February 5, 2025.](https://www.sentinelone.com/labs/lockbit-3-0-update-unpicking-the-ransomwares-latest-anti-analysis-and-evasion-techniques)
6. [Joey Chen, Cisco Talos. (2025, February 27). Lotus Blossom espionage group targets multiple industries with different versions of Sagerunex and hacking tools. Retrieved March 15, 2025.](https://blog.talosintelligence.com/lotus-blossom-espionage-group/)
7. [Malik, M. (2019, June 20). LoudMiner: Cross-platform mining in cracked VST software. Retrieved May 18, 2020.](https://www.welivesecurity.com/2019/06/20/loudminer-mining-cracked-vst-software/)
8. [Cybersecurity and Infrastructure Security Agency. (2025, March 12). AA25-071A #StopRansomware: Medusa Ransomware. Retrieved October 15, 2025.](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a)
9. [Vlad Pasca. (2024, January 1). A Deep Dive into Medusa Ransomware. Retrieved October 15, 2025.](https://securityscorecard.com/wp-content/uploads/2024/01/deep-dive-into-medusa-ransomware.pdf)
10. [Miller-Osborn, J. and Grunzweig, J.. (2017, March 30). Trochilus and New MoonWind RATs Used In Attack Against Thai Organizations. Retrieved March 30, 2017.](http://researchcenter.paloaltonetworks.com/2017/03/unit42-trochilus-rat-new-moonwind-rat-used-attack-thai-utility-organizations/)
11. [Neville, A. (2012, June 15). Trojan.Naid. Retrieved February 22, 2018.](https://www.symantec.com/security_response/writeup.jsp?docid=2012-061518-4639-99)
12. [Vrabie, V. (2021, April 23). NAIKON – Traces from a Military Cyber-Espionage Operation. Retrieved June 29, 2021.](https://www.bitdefender.com/files/News/CaseStudies/study/396/Bitdefender-PR-Whitepaper-NAIKON-creat5397-en-EN.pdf)
13. [Ladley, F. (2012, May 15). Backdoor.Nerex. Retrieved February 23, 2018.](https://www.symantec.com/security_response/writeup.jsp?docid=2012-051515-3445-99)
14. [Sponchioni, R.. (2016, March 11). Backdoor.Nidiran. Retrieved August 3, 2016.](https://www.symantec.com/security_response/writeup.jsp?docid=2015-120123-5521-99)
15. [Faou, M. (2023, August 10). MoustachedBouncer: Espionage against foreign diplomats in Belarus. Retrieved September 25, 2023.](https://www.welivesecurity.com/en/eset-research/moustachedbouncer-espionage-against-foreign-diplomats-in-belarus/)
16. [Dedola, G. (2022, June 21). APT ToddyCat. Retrieved January 3, 2024.](https://securelist.com/toddycat/106799/)
17. [Symantec Threat Hunter Team. (2023, October 19). Crambus: New Campaign Targets Middle Eastern Government. Retrieved November 27, 2024.](https://www.security.com/threat-intelligence/crambus-middle-east-government)
18. [Hromcova, Z. (2019, July). OKRUM AND KETRICAN: AN OVERVIEW OF RECENT KE3CHANG GROUP ACTIVITY. Retrieved May 6, 2020.](https://www.welivesecurity.com/wp-content/uploads/2019/07/ESET_Okrum_and_Ketrican.pdf)
19. [Cybereason Nocturnus. (2022, May 4). Operation CuckooBees: Deep-Dive into Stealthy Winnti Techniques. Retrieved September 22, 2022.](https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques)
20. [Aleksandar Milenkoski, Luigi Martire. (2024, December 10). Operation Digital Eye | Chinese APT Compromises Critical Digital Infrastructure via Visual Studio Code Tunnels. Retrieved February 27, 2025.](https://www.sentinelone.com/labs/operation-digital-eye-chinese-apt-compromises-critical-digital-infrastructure-via-visual-studio-code-tunnels/)
21. [Sherstobitoff, R. (2018, March 02). McAfee Uncovers Operation Honeybee, a Malicious Document Campaign Targeting Humanitarian Aid Groups. Retrieved May 16, 2018.](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-uncovers-operation-honeybee-malicious-document-campaign-targeting-humanitarian-aid-groups/)
22. [Lunghi, D. and Lu, K. (2021, April 9). Iron Tiger APT Updates Toolkit With Evolved SysUpdate Malware. Retrieved November 12, 2021.](https://www.trendmicro.com/en_us/research/21/d/iron-tiger-apt-updates-toolkit-with-evolved-sysupdate-malware-va.html)
23. [Unit 42. (2022, June 13). GALLIUM Expands Targeting Across Telecommunications, Government and Finance Sectors With New PingPull Tool. Retrieved August 7, 2022.](https://unit42.paloaltonetworks.com/pingpull-gallium/)
24. [Tartare, M. et al. (2020, May 21). No “Game over” for the Winnti Group. Retrieved August 24, 2020.](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/)
25. [Computer Incident Response Center Luxembourg. (2013, March 29). Analysis of a PlugX variant. Retrieved November 5, 2018.](http://circl.lu/assets/files/tr-12/tr-12-circl-plugx-analysis-v1.pdf)
26. [Vasilenko, R. (2013, December 17). An Analysis of PlugX Malware. Retrieved November 24, 2015.](https://lastline3.rssing.com/chan-29044929/all_p1.html#c29044929a2)
27. [PwC and BAE Systems. (2017, April). Operation Cloud Hopper: Technical Annex. Retrieved April 13, 2017.](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)
28. [FireEye iSIGHT Intelligence. (2017, April 6). APT10 (MenuPass Group): New Tools, Global Campaign Latest Manifestation of Longstanding Threat. Retrieved June 29, 2017.](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)
29. [Huss, D., et al. (2017, February 2). Oops, they did it again: APT Targets Russia and Belarus with ZeroT and PlugX. Retrieved April 5, 2018.](https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx)
30. [Hayashi, K. (2005, August 18). Backdoor.Darkmoon. Retrieved February 23, 2018.](https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99)
31. [PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.](https://github.com/PowerShellMafia/PowerSploit)
32. [PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.](http://powersploit.readthedocs.io)
33. [Tudorica, R. et al. (2020, June 30). StrongPity APT - Revealing Trojanized Tools, Working Hours and Infrastructure. Retrieved July 20, 2020.](https://www.bitdefender.com/files/News/CaseStudies/study/353/Bitdefender-Whitepaper-StrongPity-APT.pdf)
34. [Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.](https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx)
35. [Inman, R. and Gurney, P. (2022, June 6). Shining the Light on Black Basta. Retrieved March 8, 2023.](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/)
36. [SophosLabs. (2020, May 21). Ragnar Locker ransomware deploys virtual machine to dodge security. Retrieved June 29, 2020.](https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/)
37. [Nesbit, B. and Ackerman, D. (2017, January). Malware Analysis Report - RawPOS Malware: Deconstructing an Intruder’s Toolkit. Retrieved October 4, 2017.](https://www.kroll.com/en/insights/publications/malware-analysis-report-rawpos-malware)
38. [TrendLabs Security Intelligence Blog. (2015, April). RawPOS Technical Brief. Retrieved October 4, 2017.](http://sjc1-te-ftp.trendmicro.com/images/tex/pdf/RawPOS%20Technical%20Brief.pdf)
39. [Bromiley, M. and Lewis, P. (2016, October 7). Attacking the Hospitality and Gaming Industries: Tracking an Attacker Around the World in 7 Years. Retrieved October 6, 2017.](https://www.youtube.com/watch?v=fevGZs0EQu8)
40. [Falcone, R. (2020, July 22). OilRig Targets Middle Eastern Telecommunications Organization and Adds Novel C2 Channel with Steganography to Its Inventory. Retrieved July 28, 2020.](https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/)
41. [Grunzweig, J. and Miller-Osborn, J. (2017, November 10). New Malware with Ties to SunOrcal Discovered. Retrieved November 16, 2017.](https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/)
42. [Zhang, X. (2024, November 8). New Campaign Uses Remcos RAT to Exploit Victims. Retrieved April 16, 2026.](https://www.fortinet.com/blog/threat-research/new-campaign-uses-remcos-rat-to-exploit-victims)
43. [Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, July 30). Sakula Malware Family. Retrieved January 26, 2016.](http://www.secureworks.com/cyber-threat-intelligence/threats/sakula-malware-family/)
44. [Mandiant. (n.d.). Appendix C (Digital) - The Malware Arsenal. Retrieved July 18, 2016.](https://www.mandiant.com/sites/default/files/2021-09/mandiant-apt1-report.pdf)
45. [Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.](http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/)
46. [Falcone, R. (2018, December 13). Shamoon 3 Targets Oil and Gas Organization. Retrieved March 14, 2019.](https://unit42.paloaltonetworks.com/shamoon-3-targets-oil-gas-organization/)
47. [Yonathan Klijnsma. (2016, May 17). Mofang: A politically motivated information stealing adversary. Retrieved May 12, 2020.](https://foxitsecurity.files.wordpress.com/2016/06/fox-it_mofang_threatreport_tlp-white.pdf)
48. [Salvati, M. (2019, August 6). SILENTTRINITY Modules. Retrieved March 24, 2022.](https://github.com/byt3bl33d3r/SILENTTRINITY/tree/master/silenttrinity/core/teamserver/modules/boo)
49. [DHS/CISA, Cyber National Mission Force. (2020, October 1). Malware Analysis Report (MAR) MAR-10303705-1.v1 – Remote Access Trojan: SLOTHFULMEDIA. Retrieved October 2, 2020.](https://us-cert.cisa.gov/ncas/analysis-reports/ar20-275a)
50. [Tomcik, R. et al. (2022, February 24). Left On Read: Telegram Malware Spotted in Latest Iranian Cyber Espionage Activity. Retrieved August 18, 2022.](https://www.mandiant.com/resources/telegram-malware-iranian-espionage)
51. [Cylance SPEAR Team. (2017, February 9). Shell Crew Variants Continue to Fly Under Big AV’s Radar. Retrieved February 15, 2017.](https://www.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar)
52. [Mercer, W. et al. (2020, June 29). PROMETHIUM extends global reach with StrongPity3 APT. Retrieved July 20, 2020.](https://blog.talosintelligence.com/2020/06/promethium-extends-with-strongpity3.html)
53. [Nicolas Falliere, Liam O Murchu, Eric Chien 2011, February W32.Stuxnet Dossier (Version 1.4) Retrieved November 17, 2024.](https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier-11-en)
54. [Mandiant Israel Research Team. (2022, August 17). Suspected Iranian Actor Targeting Israeli Shipping, Healthcare, Government and Energy Sectors. Retrieved September 21, 2022.](https://www.mandiant.com/resources/blog/suspected-iranian-actor-targeting-israeli-shipping)
55. [ClearSky Cyber Security and Trend Micro. (2017, July). Operation Wilted Tulip: Exposing a cyber espionage apparatus. Retrieved August 21, 2017.](http://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf)
56. [AT&T Alien Labs. (2021, September 8). TeamTNT with new campaign aka Chimaera. Retrieved September 22, 2021.](https://cybersecurity.att.com/blogs/labs-research/teamtnt-with-new-campaign-aka-chimaera)
57. [Check Point Research. (2020, December 22). SUNBURST, TEARDROP and the NetSec New Normal. Retrieved January 6, 2021.](https://research.checkpoint.com/2020/sunburst-teardrop-and-the-netsec-new-normal/)
58. [FireEye. (2020, December 13). Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor. Retrieved January 4, 2021.](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)
59. [Pantazopoulos, N., Henry T. (2018, May 18). Emissary Panda – A potential new malicious tool. Retrieved June 25, 2018.](https://research.nccgroup.com/2018/05/18/emissary-panda-a-potential-new-malicious-tool/)
60. [Daniel Lunghi. (2023, March 1). Iron Tiger’s SysUpdate Reappears, Adds Linux Targeting. Retrieved March 20, 2023.](https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html)
61. [Vyacheslav Kopeytsev and Seongsu Park. (2021, February 25). Lazarus targets defense industry with ThreatNeedle. Retrieved October 27, 2021.](https://securelist.com/lazarus-threatneedle/100803/)
62. [Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.](https://web.archive.org/web/20200302085133/https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf)
63. [Lior Rochberger, Tom Fakterman, Robert Falcone. (2023, September 22). Cyberespionage Attacks Against Southeast Asian Government Linked to Stately Taurus, Aka Mustang Panda. Retrieved September 9, 2025.](https://unit42.paloaltonetworks.com/stately-taurus-attacks-se-asian-government/)
64. [Anthony, N., Pascual, C.. (2018, November 1). Trickbot Shows Off New Trick: Password Grabber Module. Retrieved November 16, 2018.](https://blog.trendmicro.com/trendlabs-security-intelligence/trickbot-shows-off-new-trick-password-grabber-module/)
65. [Parys, B. (2017, February 11). The KeyBoys are back in town. Retrieved June 13, 2019.](https://web.archive.org/web/20211129064701/https://www.pwc.co.uk/issues/cyber-security-services/research/the-keyboys-are-back-in-town.html)
66. [US-CERT. (2018, June 14). MAR-10135536-12 – North Korean Trojan: TYPEFRAME. Retrieved July 13, 2018.](https://www.us-cert.gov/ncas/analysis-reports/AR18-165A)
67. [FBI et al. (2023, May 9). Hunting Russian Intelligence “Snake” Malware. Retrieved June 8, 2023.](https://www.cisa.gov/sites/default/files/2023-05/aa23-129a_snake_malware_2.pdf)
68. [Trend Micro. (2014, December 11). PE\_URSNIF.A2. Retrieved June 5, 2019.](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/PE_URSNIF.A2?_ga=2.131425807.1462021705.1559742358-1202584019.1549394279)
69. [US-CERT. (2017, November 22). Alert (TA17-318B): HIDDEN COBRA – North Korean Trojan: Volgmer. Retrieved December 7, 2017.](https://www.us-cert.gov/ncas/alerts/TA17-318B)
70. [US-CERT. (2017, November 01). Malware Analysis Report (MAR) - 10135536-D. Retrieved July 16, 2018.](https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-D_WHITE_S508C.PDF)
71. [Yagi, J. (2014, August 24). Trojan.Volgmer. Retrieved July 16, 2018.](https://web.archive.org/web/20181126143456/https://www.symantec.com/security-center/writeup/2014-081811-3237-99?tabid=2)
72. [Noerenberg, E., Costis, A., and Quist, N. (2017, May 16). A Technical Analysis of WannaCry Ransomware. Retrieved December 8, 2024.](https://web.archive.org/web/20230522041200/https://logrhythm.com/blog/a-technical-analysis-of-wannacry-ransomware/)
73. [Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.](https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html)
74. [Antenucci, S., Pantazopoulos, N., Sandee, M. (2020, June 23). WastedLocker: A New Ransomware Variant Developed By The Evil Corp Group. Retrieved September 14, 2021.](https://research.nccgroup.com/2020/06/23/wastedlocker-a-new-ransomware-variant-developed-by-the-evil-corp-group/)
75. [Zhou, R. (2012, May 15). Backdoor.Wiarp. Retrieved February 22, 2018.](https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99)
76. [Anthe, C. et al. (2016, December 14). Microsoft Security Intelligence Report Volume 21. Retrieved November 27, 2017.](http://download.microsoft.com/download/E/B/0/EB0F50CC-989C-4B66-B7F6-68CD3DC90DE3/Microsoft_Security_Intelligence_Report_Volume_21_English.pdf)
77. [Microsoft. (2017, November 9). Backdoor:Win32/Wingbird.A!dha. Retrieved November 27, 2017.](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/Wingbird.A!dha)
78. [Cap, P., et al. (2017, January 25). Detecting threat actors in recent German industrial attacks with Windows Defender ATP. Retrieved February 8, 2017.](https://blogs.technet.microsoft.com/mmpc/2017/01/25/detecting-threat-actors-in-recent-german-industrial-attacks-with-windows-defender-atp/)
79. [John, E. and Carvey, H. (2019, May 30). Unraveling the Spiderweb: Timelining ATT&CK Artifacts Used by GRIM SPIDER. Retrieved May 12, 2020.](https://www.crowdstrike.com/blog/timelining-grim-spiders-big-game-hunting-tactics/)
80. [Shilko, J., et al. (2021, October 7). FIN12: The Prolific Ransomware Intrusion Threat Actor That Has Aggressively Pursued Healthcare Targets. Retrieved June 15, 2023.](https://web.archive.org/web/20220313061955/https://www.mandiant.com/sites/default/files/2021-10/fin12-group-profile.pdf)
81. [Gross, J. (2016, February 23). Operation Dust Storm. Retrieved December 22, 2021.](https://s7d2.scene7.com/is/content/cylance/prod/cylance-web/en-us/resources/knowledge-center/resource-library/reports/Op_Dust_Storm_Report.pdf)
82. [McAfee® Foundstone® Professional Services and McAfee Labs™. (2011, February 10). Global Energy Cyberattacks: “Night Dragon”. Retrieved February 19, 2018.](https://scadahacker.com/library/Documents/Cyber_Events/McAfee%20-%20Night%20Dragon%20-%20Global%20Energy%20Cyberattacks.pdf)
83. [Allievi, A., et al. (2014, October 28). Threat Spotlight: Group 72, Opening the ZxShell. Retrieved September 24, 2019.](https://blogs.cisco.com/security/talos/opening-zxshell)
84. [Azure Edge and Platform Security Team & Microsoft 365 Defender Research Team. (2021, December 8). Improve kernel security with the new Microsoft Vulnerable and Malicious Driver Reporting Center. Retrieved April 6, 2022.](https://www.microsoft.com/security/blog/2021/12/08/improve-kernel-security-with-the-new-microsoft-vulnerable-and-malicious-driver-reporting-center/)
85. [Jordan Geurten et al. . (2022, March 29). Microsoft recommended driver block rules. Retrieved April 7, 2022.](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)

[![](/theme/images/mitrelogowhiteontrans.gif)](https://www.mitre.org)

[Contact Us](/resources/engage-with-attack/contact)

[Terms of Use](/resources/legal-and-branding/terms-of-use)

[Privacy Policy](/resources/legal-and-branding/privacy)

[Website Changelog](/resources/changelog.html "ATT&CK content v19.1Website  v4.4.3")

[Cookie Preferences](/resources/legal-and-branding/privacy/#)

© 2015 - 2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.