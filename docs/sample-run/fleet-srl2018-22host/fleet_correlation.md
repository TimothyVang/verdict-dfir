# Fleet correlation report

**Fleet dir:** `fleet-20260609T162206Z`
**Host count:** 22

## Verdict distribution

| Verdict | Count |
|---|---:|
| **INDETERMINATE** | 22 |

## MITRE ATT&CK technique density across the fleet

| Technique | Hosts |
|---|---:|
| T1055 | 7 |

## Cross-host process-name correlation

*Uncommon process names that appear on ≥2 hosts. Same name across multiple hosts is a much stronger lateral-movement signal than the same name on one host alone.*

| Image name | Host count | Hosts (first 5) |
|---|---:|---|
| `subject_srv.ex` | 20 | base-admin-memory, base-av-memory, base-dc-memory, base-elf-memory, base-file |
| `cmd.exe` | 17 | base-admin-memory, base-av-memory, base-dc-memory, base-elf-memory, base-file |
| `powershell.exe` | 15 | base-admin-memory, base-dc-memory, base-file, base-file-snapshot5, base-mail-memory |
| `rubyw.exe` | 14 | base-admin-memory, base-av-memory, base-file, base-file-snapshot5, base-hunt-memory |
| `ruby.exe` | 12 | base-admin-memory, base-av-memory, base-hunt-memory, base-rd-02-memory, base-rd-03-memory |
| `plasrv.exe` | 9 | base-admin-memory, base-av-memory, base-rd-03-memory, base-rd-04-memory, base-sp-memory |
| `rundll32.exe` | 8 | base-dc-memory, base-file, base-file-snapshot5, base-mail-memory, base-rd-04-memory |
| `rdpinput.exe` | 8 | base-admin-memory, base-av-memory, base-dc-memory, base-elf-memory, base-file |
| `ncpa_passive.e` | 8 | base-av-memory, base-file, base-file-snapshot5, base-rd-05-memory, base-rd-06-memory |
| `ncpa_listener.` | 8 | base-av-memory, base-file, base-file-snapshot5, base-rd-05-memory, base-rd-06-memory |
| `msadvapi2_32.e` | 8 | base-rd-02-memory, base-rd-03-memory, base-rd-05-memory, base-rd-06-memory, base-wkstn-02-memory |
| `msadvapi2_64.e` | 8 | base-rd-02-memory, base-rd-03-memory, base-rd-05-memory, base-rd-06-memory, base-wkstn-02-memory |
| `java.exe` | 8 | base-rd-02-memory, base-rd-03-memory, base-rd-05-memory, base-rd-06-memory, base-wkstn-02-memory |
| `prunsrv.exe` | 8 | base-rd-02-memory, base-rd-03-memory, base-rd-05-memory, base-rd-06-memory, base-wkstn-02-memory |
| `OUTLOOK.EXE` | 8 | base-rd-02-memory, base-rd-04-memory, base-rd01-memory, base-wkstn-01-memory, base-wkstn-02-memory |
| `find.exe` | 8 | base-admin-memory, base-rd-02-memory, base-rd-03-memory, base-rd-05-memory, base-rd-06-memory |
| `chrome.exe` | 7 | base-admin-memory, base-av-memory, base-rd-02-memory, base-rd-04-memory, base-wkstn-02-memory |
| `sppsvc.exe` | 7 | base-rd-02-memory, base-rd-03-memory, base-sp-memory, base-wkstn-01-memory, base-wkstn-02-memory |
| `SkypeHost.exe` | 7 | base-admin-memory, base-hunt-memory, base-rd-03-memory, base-rd-04-memory, base-rd01-memory |
| `mmc.exe` | 6 | base-dc-memory, base-elf-memory, base-file, base-file-snapshot5, base-rd-03-memory |
| `sc.exe` | 6 | base-rd-02-memory, base-rd-03-memory, base-rd-05-memory, base-rd-06-memory, base-wkstn-01-memory |
| `NETSTAT.EXE` | 6 | base-rd-02-memory, base-rd-03-memory, base-rd-05-memory, base-rd-06-memory, base-wkstn-02-memory |
| `iexplore.exe` | 6 | base-av-memory, base-mail-memory, base-rd-04-memory, base-rd01-memory, base-sp-memory |
| `Autorunsc.exe` | 6 | base-rd-04-memory, base-rd-05-memory, base-wkstn-01-memory, base-wkstn-02-memory, base-wkstn-03-memory |
| `armsvc.exe` | 6 | base-hunt-memory, base-rd-04-memory, base-rd01-memory, base-wkstn-01-mem, base-wkstn-01-memory |
| `ServerManager.` | 5 | base-dc-memory, base-elf-memory, base-file, base-file-snapshot5, base-mail-memory |
| `MicrosoftEdge.` | 5 | base-admin-memory, base-hunt-memory, base-rd-04-memory, base-wkstn-02-memory, base-wkstn-03-memory |
| `taskhostex.exe` | 4 | base-av-memory, base-file, base-file-snapshot5, base-sp-memory |
| `TSTheme.exe` | 4 | base-av-memory, base-file, base-file-snapshot5, base-sp-memory |
| `nscp.exe` | 4 | base-av-memory, base-file, base-file-snapshot5, base-sp-memory |
| `firefox.exe` | 4 | base-wkstn-01-memory, base-wkstn-02-memory, base-wkstn-03-memory, base-wkstn-06-memory |
| `AppVShNotify.e` | 4 | base-rd-04-memory, base-rd01-memory, base-wkstn-01-mem, base-wkstn-01-memory |
| `GoogleUpdate.e` | 4 | base-rd-05-memory, base-wkstn-02-memory, base-wkstn-03-memory, base-wkstn-04-memory |
| `TabTip32.exe` | 4 | base-admin-memory, base-dc-memory, base-elf-memory, base-mail-memory |
| `POWERPNT.EXE` | 3 | base-wkstn-02-memory, base-wkstn-03-memory, base-wkstn-06-memory |
| `taskeng.exe` | 3 | base-rd-05-memory, base-rd-06-memory, base-wkstn-06-memory |
| `TiWorker.exe` | 3 | base-av-memory, base-rd-02-memory, base-rd-04-memory |
| `OneDriveSetup.` | 3 | base-rd-03-memory, base-wkstn-02-memory, base-wkstn-03-memory |
| `HxTsr.exe` | 3 | base-hunt-memory, base-rd-04-memory, base-rd01-memory |
| `dmclient.exe` | 3 | base-admin-memory, base-rd-04-memory, base-wkstn-01-memory |
| `SettingSyncHos` | 3 | base-rd-04-memory, base-rd01-memory, base-wkstn-01-memory |
| `MicrosoftEdgeC` | 3 | base-admin-memory, base-hunt-memory, base-wkstn-02-memory |
| `browser_broker` | 3 | base-admin-memory, base-hunt-memory, base-wkstn-02-memory |
| `notepad.exe` | 3 | base-admin-memory, base-dc-memory, base-sp-memory |
| `Rar.exe` | 2 | base-file, base-file-snapshot5 |
| `ngentask.exe` | 2 | base-file, base-rd-04-memory |
| `WINWORD.EXE` | 2 | base-wkstn-03-memory, base-wkstn-06-memory |
| `EXCEL.EXE` | 2 | base-wkstn-03-memory, base-wkstn-06-memory |
| `certutil.exe` | 2 | base-wkstn-03-memory, base-wkstn-06-memory |
| `splwow64.exe` | 2 | base-wkstn-03-memory, base-wkstn-06-memory |
| `WmiApSrv.exe` | 2 | base-rd-02-memory, base-rd01-memory |
| `AdobeARMHelper` | 2 | base-rd-04-memory, base-wkstn-01-memory |
| `DashlanePlugin` | 2 | base-rd-04-memory, base-rd01-memory |
| `MusNotificatio` | 2 | base-elf-memory, base-rd-04-memory |
| `ngen.exe` | 2 | base-admin-memory, base-rd-04-memory |
| `Dashlane.exe` | 2 | base-rd-04-memory, base-rd01-memory |
| `dstokenclean.e` | 2 | base-rd-04-memory, base-wkstn-01-memory |
| `software_repor` | 2 | base-av-memory, base-rd-04-memory |
| `WinStore.App.e` | 2 | base-rd01-memory, base-wkstn-03-memory |
| `unsecapp.exe` | 2 | base-wkstn-01-mem, base-wkstn-05-memory |
| `Windows.WARP.J` | 2 | base-admin-memory, base-wkstn-02-memory |
| `Taskmgr.exe` | 2 | base-dc-memory, base-sp-memory |
| `LockAppHost.ex` | 2 | base-dc-memory, base-elf-memory |
| `tasklist.exe` | 2 | base-dc-memory, base-elf-memory |
| `nxlog.exe` | 2 | base-elf-memory, base-mail-memory |
| `sqlservr.exe` | 2 | base-av-memory, base-sp-memory |
| `sqlwriter.exe` | 2 | base-av-memory, base-sp-memory |
| `fdhost.exe` | 2 | base-av-memory, base-sp-memory |
| `fdlauncher.exe` | 2 | base-av-memory, base-sp-memory |
| `w3wp.exe` | 2 | base-mail-memory, base-sp-memory |
| `noderunner.exe` | 2 | base-mail-memory, base-sp-memory |
| `inetinfo.exe` | 2 | base-mail-memory, base-sp-memory |
| `hostcontroller` | 2 | base-mail-memory, base-sp-memory |
| `SMSvcHost.exe` | 2 | base-mail-memory, base-sp-memory |

## Temporal clusters

*Groups of process creations across multiple hosts that fall within a 60-second window. Tight time clusters spanning ≥2 hosts are a hallmark of automated lateral movement (PsExec waves, WMI execution, scheduled-task chains).*

### Cluster 1: 5 hosts in 312.0s (2018-06-04T20:18:02+00:00 → 2018-06-04T20:23:14+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-elf-memory` | 2018-06-04T20:18:02+00:00 | 4 | `System` |
| `base-elf-memory` | 2018-06-04T20:18:02+00:00 | 4 | `System` |
| `base-elf-memory` | 2018-06-04T20:18:02+00:00 | 296 | `smss.exe` |
| `base-elf-memory` | 2018-06-04T20:18:15+00:00 | 392 | `csrss.exe` |
| `base-elf-memory` | 2018-06-04T20:18:16+00:00 | 472 | `smss.exe` |
| `base-elf-memory` | 2018-06-04T20:18:16+00:00 | 504 | `wininit.exe` |
| `base-elf-memory` | 2018-06-04T20:18:16+00:00 | 480 | `csrss.exe` |
| `base-elf-memory` | 2018-06-04T20:18:17+00:00 | 536 | `winlogon.exe` |
| `base-elf-memory` | 2018-06-04T20:18:19+00:00 | 616 | `services.exe` |
| `base-elf-memory` | 2018-06-04T20:18:20+00:00 | 632 | `lsass.exe` |
| `base-elf-memory` | 2018-06-04T20:18:24+00:00 | 724 | `svchost.exe` |
| `base-elf-memory` | 2018-06-04T20:18:25+00:00 | 788 | `svchost.exe` |
| `base-elf-memory` | 2018-06-04T20:18:28+00:00 | 328 | `svchost.exe` |
| `base-elf-memory` | 2018-06-04T20:18:28+00:00 | 268 | `svchost.exe` |
| `base-elf-memory` | 2018-06-04T20:18:28+00:00 | 1004 | `svchost.exe` |
| `base-elf-memory` | 2018-06-04T20:18:28+00:00 | 996 | `svchost.exe` |
| `base-elf-memory` | 2018-06-04T20:18:28+00:00 | 888 | `dwm.exe` |
| `base-elf-memory` | 2018-06-04T20:18:28+00:00 | 912 | `svchost.exe` |
| `base-elf-memory` | 2018-06-04T20:18:34+00:00 | 1076 | `svchost.exe` |
| `base-elf-memory` | 2018-06-04T20:18:34+00:00 | 1120 | `vmacthlp.exe` |

### Cluster 2: 3 hosts in 33.0s (2018-07-07T03:31:00+00:00 → 2018-07-07T03:31:33+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-wkstn-04-memory` | 2018-07-07T03:31:00+00:00 | 4236 | `GoogleUpdate.e` |
| `base-rd-05-memory` | 2018-07-07T03:31:25+00:00 | 9704 | `GoogleUpdate.e` |
| `base-wkstn-03-memory` | 2018-07-07T03:31:33+00:00 | 5640 | `GoogleUpdate.e` |

### Cluster 3: 2 hosts in 1.0s (2018-07-27T15:49:09+00:00 → 2018-07-27T15:49:10+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-rd-05-memory` | 2018-07-27T15:49:09+00:00 | 14612 | `winlogon.exe` |
| `base-rd-05-memory` | 2018-07-27T15:49:09+00:00 | 14580 | `csrss.exe` |
| `base-wkstn-04-memory` | 2018-07-27T15:49:09+00:00 | 2712 | `smss.exe` |
| `base-wkstn-04-memory` | 2018-07-27T15:49:09+00:00 | 5692 | `dwm.exe` |
| `base-wkstn-04-memory` | 2018-07-27T15:49:09+00:00 | 5812 | `csrss.exe` |
| `base-wkstn-04-memory` | 2018-07-27T15:49:09+00:00 | 392 | `winlogon.exe` |
| `base-wkstn-04-memory` | 2018-07-27T15:49:09+00:00 | 196 | `fontdrvhost.ex` |
| `base-wkstn-04-memory` | 2018-07-27T15:49:09+00:00 | 2880 | `LogonUI.exe` |
| `base-rd-05-memory` | 2018-07-27T15:49:10+00:00 | 5000 | `LogonUI.exe` |

### Cluster 4: 2 hosts in 11.0s (2018-08-08T18:07:56+00:00 → 2018-08-08T18:08:07+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-file-snapshot5` | 2018-08-08T18:07:56+00:00 | 244 | `smss.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:56+00:00 | 4 | `System` |
| `base-file` | 2018-08-08T18:07:56+00:00 | 244 | `smss.exe` |
| `base-file` | 2018-08-08T18:07:56+00:00 | 4 | `System` |
| `base-file-snapshot5` | 2018-08-08T18:07:57+00:00 | 368 | `csrss.exe` |
| `base-file` | 2018-08-08T18:07:57+00:00 | 368 | `csrss.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:58+00:00 | 544 | `lsass.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:58+00:00 | 496 | `winlogon.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:58+00:00 | 536 | `services.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:58+00:00 | 436 | `csrss.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:58+00:00 | 444 | `wininit.exe` |
| `base-file` | 2018-08-08T18:07:58+00:00 | 544 | `lsass.exe` |
| `base-file` | 2018-08-08T18:07:58+00:00 | 496 | `winlogon.exe` |
| `base-file` | 2018-08-08T18:07:58+00:00 | 536 | `services.exe` |
| `base-file` | 2018-08-08T18:07:58+00:00 | 436 | `csrss.exe` |
| `base-file` | 2018-08-08T18:07:58+00:00 | 444 | `wininit.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:59+00:00 | 600 | `svchost.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:59+00:00 | 632 | `svchost.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:59+00:00 | 724 | `LogonUI.exe` |
| `base-file-snapshot5` | 2018-08-08T18:07:59+00:00 | 744 | `svchost.exe` |

### Cluster 5: 2 hosts in 3.0s (2018-08-08T18:10:06+00:00 → 2018-08-08T18:10:09+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-file-snapshot5` | 2018-08-08T18:10:06+00:00 | 2848 | `ncpa_listener.` |
| `base-file` | 2018-08-08T18:10:06+00:00 | 2848 | `ncpa_listener.` |
| `base-file-snapshot5` | 2018-08-08T18:10:09+00:00 | 2868 | `ncpa_passive.e` |
| `base-file` | 2018-08-08T18:10:09+00:00 | 2868 | `ncpa_passive.e` |

### Cluster 6: 2 hosts in 40.0s (2018-08-12T04:52:14+00:00 → 2018-08-12T04:52:54+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-file-snapshot5` | 2018-08-12T04:52:14+00:00 | 820 | `csrss.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:14+00:00 | 2416 | `winlogon.exe` |
| `base-file` | 2018-08-12T04:52:14+00:00 | 820 | `csrss.exe` |
| `base-file` | 2018-08-12T04:52:14+00:00 | 2416 | `winlogon.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:15+00:00 | 2260 | `dwm.exe` |
| `base-file` | 2018-08-12T04:52:15+00:00 | 2260 | `dwm.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:16+00:00 | 1528 | `rdpinput.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:16+00:00 | 3844 | `explorer.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:16+00:00 | 3728 | `rdpclip.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:16+00:00 | 3536 | `taskhostex.exe` |
| `base-file` | 2018-08-12T04:52:16+00:00 | 1528 | `rdpinput.exe` |
| `base-file` | 2018-08-12T04:52:16+00:00 | 3844 | `explorer.exe` |
| `base-file` | 2018-08-12T04:52:16+00:00 | 3728 | `rdpclip.exe` |
| `base-file` | 2018-08-12T04:52:16+00:00 | 3536 | `taskhostex.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:28+00:00 | 2604 | `vmtoolsd.exe` |
| `base-file` | 2018-08-12T04:52:28+00:00 | 2604 | `vmtoolsd.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:35+00:00 | 3320 | `mmc.exe` |
| `base-file` | 2018-08-12T04:52:35+00:00 | 3320 | `mmc.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:50+00:00 | 3880 | `cmd.exe` |
| `base-file-snapshot5` | 2018-08-12T04:52:50+00:00 | 2464 | `conhost.exe` |

### Cluster 7: 6 hosts in 0.0s (2018-08-15T17:10:32+00:00 → 2018-08-15T17:10:32+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-rd-04-memory` | 2018-08-15T17:10:32+00:00 | 2256 | `Autorunsc.exe` |
| `base-rd-05-memory` | 2018-08-15T17:10:32+00:00 | 19176 | `Autorunsc.exe` |
| `base-wkstn-01-memory` | 2018-08-15T17:10:32+00:00 | 9048 | `Autorunsc.exe` |
| `base-wkstn-02-memory` | 2018-08-15T17:10:32+00:00 | 6516 | `Autorunsc.exe` |
| `base-wkstn-03-memory` | 2018-08-15T17:10:32+00:00 | 728 | `Autorunsc.exe` |
| `base-wkstn-04-memory` | 2018-08-15T17:10:32+00:00 | 7092 | `Autorunsc.exe` |

### Cluster 8: 2 hosts in 15.0s (2018-08-17T15:22:33+00:00 → 2018-08-17T15:22:48+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-dc-memory` | 2018-08-17T15:22:33+00:00 | 4292 | `mmc.exe` |
| `base-rd-04-memory` | 2018-08-17T15:22:48+00:00 | 4620 | `plasrv.exe` |

### Cluster 9: 2 hosts in 7.0s (2018-08-19T04:00:27+00:00 → 2018-08-19T04:00:34+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-file-snapshot5` | 2018-08-19T04:00:27+00:00 | 4736 | `ServerManager.` |
| `base-file` | 2018-08-19T04:00:27+00:00 | 4736 | `ServerManager.` |
| `base-file-snapshot5` | 2018-08-19T04:00:34+00:00 | 3516 | `mmc.exe` |
| `base-file` | 2018-08-19T04:00:34+00:00 | 3516 | `mmc.exe` |

### Cluster 10: 2 hosts in 216.0s (2018-08-19T06:22:43+00:00 → 2018-08-19T06:26:19+00:00)

| Host | Time | PID | Image name |
|---|---|---:|---|
| `base-rd-02-memory` | 2018-08-19T06:22:43+00:00 | 4 | `System` |
| `base-rd-02-memory` | 2018-08-19T06:22:43+00:00 | 384 | `smss.exe` |
| `base-rd-02-memory` | 2018-08-19T06:22:43+00:00 | 4 | `System` |
| `base-rd-02-memory` | 2018-08-19T06:23:04+00:00 | 540 | `smss.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:05+00:00 | 552 | `csrss.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:05+00:00 | 684 | `winlogon.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:05+00:00 | 628 | `wininit.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:05+00:00 | 760 | `services.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:05+00:00 | 768 | `lsass.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:06+00:00 | 876 | `svchost.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:06+00:00 | 896 | `fontdrvhost.ex` |
| `base-rd-02-memory` | 2018-08-19T06:23:06+00:00 | 996 | `svchost.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:09+00:00 | 1216 | `svchost.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:09+00:00 | 1392 | `vmacthlp.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:09+00:00 | 476 | `svchost.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:09+00:00 | 836 | `svchost.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:09+00:00 | 544 | `svchost.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:09+00:00 | 624 | `svchost.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:09+00:00 | 1048 | `svchost.exe` |
| `base-rd-02-memory` | 2018-08-19T06:23:09+00:00 | 1092 | `svchost.exe` |


## Cryptographic attestation across the fleet

All 0 per-host manifests have Merkle roots; **0 unique values** (all unique — chain integrity intact).

Each per-host manifest is independently verifiable via `manifest_verify`. The fleet correlation report (this file) is **derivative**, not authoritative — it summarizes the per-host manifests but doesn't replace them. A judge / counter-party who wants to verify must verify each `run.manifest.json` individually.

## Recommended next steps for the analyst

1. Triage the SUSPICIOUS-tier hosts first (verdict distribution above).
2. For any cross-host process appearing on ≥3 hosts, pull the binary off disk (via the corresponding host's E01) and YARA-scan it.
3. For temporal clusters spanning ≥3 hosts, build a timeline of the cluster's events and look for the *first* host in the cluster — that's the patient zero candidate.
4. Cross-reference any T1014 (Rootkit) hosts against the disk image's `\Windows\System32\drivers\` for unsigned drivers.

---

## Judge self-score (fleet aggregate)

*No host emitted `kind=judge_selfscore` audit records. This fleet predates commit 94c08dd which wired the selfscore step into find-evil-auto. Re-run any host with the current orchestrator and the records will appear in audit.jsonl + the per-case REPORT.pdf.*

---

*This report was produced by `fleet_correlate.py` as a derivative summary of the fleet's per-host investigations. The authoritative evidence is the set of per-host `run.manifest.json` files in each case directory.*