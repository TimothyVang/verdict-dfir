---
source_url: https://github.com/WithSecureLabs/chainsaw/wiki/Shimcache-Analysis
retrieved: 2026-06-06
fetched_with: scrapling extract get --ai-targeted
trust: UNTRUSTED third-party content captured for DFIR claim substantiation; verify against the live source before relying. Copyright remains with the original publisher (WithSecure).
---

> Source: https://github.com/WithSecureLabs/chainsaw/wiki/Shimcache-Analysis
> Retrieved 2026-06-06 via Scrapling (get).
> Corroborates the Mandiant "Caching Out" ShimCache findings (insertion-order, presence != execution).

---

[Skip to content](#start-of-content)




Navigation Menu
---------------

Toggle navigation

[Sign in](/login?return_to=https%3A%2F%2Fgithub.com%2FWithSecureLabs%2Fchainsaw%2Fwiki%2FShimcache-Analysis)

Appearance settings

* Platform

  + AI CODE CREATION
    - [GitHub CopilotWrite better code with AI](https://github.com/features/copilot)
    - [GitHub Copilot appDirect agents from issue to merge](https://github.com/features/ai/github-app)
    - [MCP RegistryNewIntegrate external tools](https://github.com/mcp)
  + DEVELOPER WORKFLOWS
    - [ActionsAutomate any workflow](https://github.com/features/actions)
    - [CodespacesInstant dev environments](https://github.com/features/codespaces)
    - [IssuesPlan and track work](https://github.com/features/issues)
    - [Code ReviewManage code changes](https://github.com/features/code-review)
  + APPLICATION SECURITY
    - [GitHub Advanced SecurityFind and fix vulnerabilities](https://github.com/security/advanced-security)
    - [Code securitySecure your code as you build](https://github.com/security/advanced-security/code-security)
    - [Secret protectionStop leaks before they start](https://github.com/security/advanced-security/secret-protection)
  + EXPLORE
    - [Why GitHub](https://github.com/why-github)
    - [Documentation](https://docs.github.com)
    - [Blog](https://github.blog)
    - [Changelog](https://github.blog/changelog)
    - [Marketplace](https://github.com/marketplace)

  [View all features](https://github.com/features)
* Solutions

  + BY COMPANY SIZE
    - [Enterprises](https://github.com/enterprise)
    - [Small and medium teams](https://github.com/team)
    - [Startups](https://github.com/enterprise/startups)
    - [Nonprofits](https://github.com/solutions/industry/nonprofits)
  + BY USE CASE
    - [App Modernization](https://github.com/solutions/use-case/app-modernization)
    - [DevSecOps](https://github.com/solutions/use-case/devsecops)
    - [DevOps](https://github.com/solutions/use-case/devops)
    - [CI/CD](https://github.com/solutions/use-case/ci-cd)
    - [View all use cases](https://github.com/solutions/use-case)
  + BY INDUSTRY
    - [Healthcare](https://github.com/solutions/industry/healthcare)
    - [Financial services](https://github.com/solutions/industry/financial-services)
    - [Manufacturing](https://github.com/solutions/industry/manufacturing)
    - [Government](https://github.com/solutions/industry/government)
    - [View all industries](https://github.com/solutions/industry)

  [View all solutions](https://github.com/solutions)
* Resources

  + EXPLORE BY TOPIC
    - [AI](https://github.com/resources/articles?topic=ai)
    - [Software Development](https://github.com/resources/articles?topic=software-development)
    - [DevOps](https://github.com/resources/articles?topic=devops)
    - [Security](https://github.com/resources/articles?topic=security)
    - [View all topics](https://github.com/resources/articles)
  + EXPLORE BY TYPE
    - [Customer stories](https://github.com/customer-stories)
    - [Events & webinars](https://github.com/resources/events)
    - [Ebooks & reports](https://github.com/resources/whitepapers)
    - [Business insights](https://github.com/solutions/executive-insights)
    - [GitHub Skills](https://skills.github.com)
  + SUPPORT & SERVICES
    - [Documentation](https://docs.github.com)
    - [Customer support](https://support.github.com)
    - [Community forum](https://github.com/orgs/community/discussions)
    - [Trust center](https://github.com/trust-center)
    - [Partners](https://github.com/partners)

  [View all resources](https://github.com/resources)
* Open Source

  + COMMUNITY
    - [GitHub SponsorsFund open source developers](https://github.com/sponsors)
  + PROGRAMS
    - [Security Lab](https://securitylab.github.com)
    - [Maintainer Community](https://maintainers.github.com)
    - [Accelerator](https://github.com/accelerator)
    - [GitHub Stars](https://stars.github.com)
    - [Archive Program](https://archiveprogram.github.com)
  + REPOSITORIES
    - [Topics](https://github.com/topics)
    - [Trending](https://github.com/trending)
    - [Collections](https://github.com/collections)
* Enterprise

  + ENTERPRISE SOLUTIONS
    - [Enterprise platformAI-powered developer platform](https://github.com/enterprise)
  + AVAILABLE ADD-ONS
    - [GitHub Advanced SecurityEnterprise-grade security features](https://github.com/security/advanced-security)
    - [Copilot for BusinessEnterprise-grade AI features](https://github.com/features/copilot/copilot-business)
    - [Premium SupportEnterprise-grade 24/7 support](https://github.com/premium-support)
* [Pricing](https://github.com/pricing)

Search or jump to...


Search code, repositories, users, issues, pull requests...
==========================================================

Search

Clear

[Search syntax tips](https://docs.github.com/search-github/github-code-search/understanding-github-code-search-syntax)

Provide feedback
================

We read every piece of feedback, and take your input very seriously.

Include my email address so I can be contacted

Cancel
 Submit feedback

Saved searches
==============

Use saved searches to filter your results more quickly
------------------------------------------------------

Name

Query

To see all available qualifiers, see our [documentation](https://docs.github.com/search-github/github-code-search/understanding-github-code-search-syntax).

Cancel
 Create saved search

[Sign in](/login?return_to=https%3A%2F%2Fgithub.com%2FWithSecureLabs%2Fchainsaw%2Fwiki%2FShimcache-Analysis)

[Sign up](/signup?ref_cta=Sign+up&ref_loc=header+logged+out&ref_page=%2F%3Cuser-name%3E%2F%3Crepo-name%3E%2Fwiki%2Fshow&source=header-repo&source_repo=WithSecureLabs%2Fchainsaw)

Appearance settings

Resetting focus

You signed in with another tab or window. Reload to refresh your session.
You signed out in another tab or window. Reload to refresh your session.
You switched accounts on another tab or window. Reload to refresh your session.
 Dismiss alert

[WithSecureLabs](/WithSecureLabs) 
/
**[chainsaw](/WithSecureLabs/chainsaw)**
Public

* [Notifications](/login?return_to=%2FWithSecureLabs%2Fchainsaw) You must be signed in to change notification settings
* [Fork
  299](/login?return_to=%2FWithSecureLabs%2Fchainsaw)
* [Star
   3.6k](/login?return_to=%2FWithSecureLabs%2Fchainsaw)

* [Code](/WithSecureLabs/chainsaw)
* [Issues
  4](/WithSecureLabs/chainsaw/issues)
* [Pull requests
  0](/WithSecureLabs/chainsaw/pulls)
* [Discussions](/WithSecureLabs/chainsaw/discussions)
* [Actions](/WithSecureLabs/chainsaw/actions)
* [Projects](/WithSecureLabs/chainsaw/projects)
* [Wiki](/WithSecureLabs/chainsaw/wiki)
* [Security and quality
  0](/WithSecureLabs/chainsaw/security)
* [Insights](/WithSecureLabs/chainsaw/pulse)

Shimcache Analysis
==================

[Jump to bottom](#wiki-pages-box)

Alex Kornitzer edited this page Apr 13, 2023
·
[2 revisions](/WithSecureLabs/chainsaw/wiki/Shimcache-Analysis/_history)

Overview
========

The Shimcache is a component of the Windows Application Experience and Compatibility feature. It is used for quick lookups on program execution to determine if a compatibility layer (a “shim”) is needed to run the application. It is stored in the `SYSTEM` windows registry hive which can be found at `C:\windows\system32\config\SYSTEM`. This artefact is widely used in the industry to identify malicious binaries threat actor may have interacted with.

The list of Shimcache entries is essentially a top-down list of events related to executables. These events are the first time an executable was shimmed. This effectively means, the executable was scanned by the Windows operating system to determine the ideal profile to run the executable in. Although the direct circumstances when Shimcache shims an executable are undocumented, we know that shimming takes place when a user interacts with an executable. This may be as simple as the user installing a program that is dropping the executable, executing it for the first time or simply creating it on the computer disk. However, one crucial fact is that the Shimcache does not contain entry insertion timestamps, but rather `last modified` timestamps of the referred files.

![Tool output example](https://user-images.githubusercontent.com/2750747/231517886-8682b3b6-05e2-42b2-ad59-ddd9e3d5220e.png)

Analysis Techniques of Determining Shimcache Insertion Timestamps
=================================================================

This analysis utilises a series of techniques to identify Shimcache insertion timestamps. The idea of the analysis is to determine accurate insertion timestamps for as many Shimcache entries as possible. This is done to provide defenders more context around what the threat actors may have executed or done on a box. As threat actors download their tools on disk shortly before execution, the timestamps determined are almost certainly the time of execution, if not shortly before execution.

Furthermore, having an accurate timestamp for Shimcache entries means that timing information of surrounding entries can be inferred:

* Every entry that is below a timestamped entry was inserted before the timestamped entry
* Every entry above a timestamped entry was inserted after the timestamped entry

The more timestamps there are, the tighter the time ranges of other entries in the Shimcache become. This allows for more accurate timing information about the existence of a file/program on a system, and in some cases, execution timing. The figure below shows a snippet of the analysis output and demonstrates derived timestamps. It also demonstrates how time ranges for the entries without timestamps can be determined.

![Timeline timeframes](https://user-images.githubusercontent.com/2750747/231518088-8b6a4bcd-0574-4476-a098-4e7dc7803f78.png)

It should be also noted that Shimcache contains a maximum of 1024 entries. The WithSecure Incident Response team found that this analysis technique tends to be more effective on Windows servers where user interaction is minimal compared to Windows workstations.

There are three different analysis techniques that can be applied to the Shimcache and Amcache. Techniques 1 and 3 have been applied in an actual incident and are tested, but with a few caveats. Technique 2 is based on new research. It is not enabled by default since it has a few theoretical edge cases where it produces false results. The below figure illustrates the flow of the analysis process.

![Shimcache analysis flowchart](https://user-images.githubusercontent.com/2750747/231518183-cba5bcad-1906-46ec-ab89-c9ba6bf90474.jpg)

Amcache Enrichments
-------------------

The Amcache is also a component of the Windows Application Experience and Compatibility feature like the Shimcache. It is a windows registry hive file that contains various metadata on programs, application files, and drivers. It is located at `C:\Windows\appcompat\Programs\Amcache.hve`.

The Amcache contains useful initial execution timestamps that can be used to enrich the timing information of Shimcache entries. The diagram below shows the differences of how many more timestamps can be derived if Amcache enrichment is enabled. We found in our tests that, Amcache enrichment leads to 2.7x more timestamps on average as well as providing SHA1 for some of the entries.

![A timeline with and without Amcache enrichments](https://user-images.githubusercontent.com/2750747/231518285-3445a6e5-3349-405b-9160-43a019664ba0.png)

Techniques
----------

### Technique 1 (T1) – Regex Rules

Required parameters: `--regexfile <path>` or `-e <pattern>`
During several incident response engagements, the WithSecure IR team observed that certain executables have a file last modified timestamp that corresponds to their first execution time. This behavior was originally observed in a [blog post by Madiant](https://www.mandiant.com/resources/blog/caching-out-the-val). Such executables are usually automatically downloaded update files or executables related to an installation that are downloaded and executed right after download.

First, all the Shimcache file paths are converted to lower-case. After this the regex rules are matched against the lower-case paths of the entries. If the regex matches, the last modified file time of the Shimcache entry is interpreted as the insertion timestamp of the same entry.

A list of provided regex rules matching to such executables available at [analysis/shimcache\_patterns.txt](https://github.com/WithSecureLabs/chainsaw/blob/master/analysis/shimcache_patterns.txt). The list is based on incidents we have dealt with and generated test data.

### Technique 2 (T2) – Shimcache Amcache Near Timestamp Pair Detection

Required parameters: `--amcache <Amcache.hve> --tspair`

If the Shimcache `file last modified timestamp` and the `amcache key update timestamp` for a file are near each other (less than `60` seconds), it is highly likely that the entry was inserted to the Shimcache at one of those timestamps. The `amcache key update timestamp` gets interpreted as the Shimcache insertion timestamp in this case.

This technique is not enabled by default since it has a few edge cases where it could produce false timestamps. These cases are covered in the [caveats and edge cases section](#t2--shimcache-amcache-near-timestamp-pair-detection-caveats-and-edge-cases).

### Technique 3 (T3) – Shimcache Amcache Timestamp Range Matching

Required parameters: `--amcache <Amcache.hve>`

This technique is based on the fact that the Shimcache insertion timestamp often corresponds to the first execution timestamp of an executable. This is also true for the entries in Amcache. This leads to a new conclusion.

Once we applied technique 1 and optionally 2, the insertion time ranges of Shimcache entries are determined. So, if an Amcache entry falls within this range and has a matching Shimcache entry with the same file path, it can be determined that the Shimcache insertion timestamp must be near if not same as the Amcache timestamp.

Accuracy caveats and edge cases
===============================

Because the Shimcache insertion timestamp are interpreted from other timestamps, they will never be absolutely accurate. This may cause the timeline timestamps to be out of order. An analyst should be aware of these limitations when performing investigations with this tool.

T1 – Regex rules detection caveats
----------------------------------

The timestamps that come from using this method are always going to be slightly before the actual Shimcache insertion time. This is due to the order of events that lead to the matched executables being inserted to the Shimcache:

1. The executable file gets created (`file last modified timestamp` created)
2. Delay
3. The executable gets either executed or scanned and inserted to the Shimcache (actual insertion timestamp)

Depending on the executable, the delay could be milliseconds, seconds, or even minutes at worst. However, even the executables that have longer delays are still worth including in some cases. They can still provide useful timing information in long running timelines with large time gaps between events.

Some executables have more accurate timestamps than others. This factor should be taken into account when picking the patterns that are used in the analysis.

T2 – Shimcache Amcache Near Timestamp Pair Detection Caveats and Edge Cases
---------------------------------------------------------------------------

### Maximum time difference between the timestamp pair

The current maximum time difference between the timestamps is 60 seconds. This essentially means that there is a +-60 second margin of error on the timestamps. This may introduce out of order timestamps.

### The Amcache timestamp is interpreted as the timeline timestamp

In some cases, it might be that the Shimcache `file last modified timestamp` is closer to the actual insertion timestamp. Currently the `amcache key update timestamp` is always used as the timeline timestamp since it often corresponds to the actual execution time. In some cases, this might introduce some inaccuracies to the timeline timestamps.

### Theoretical edge cases

There are a few theoretical edge cases which may cause false timestamps with the timestamp near pair technique. These have not been observed in real data, but they are possible in theory.

#### Spoofed or wrong file last modified timestamps in the Shimcache

It is possible to spoof file timestamps and therefore timestamps in the Shimcache. This allows the insertion/update of Shimcache entries with arbitrary timestamps. If the wrong or spoofed timestamp corresponds with an Amcache timestamp, a false detection occurs.

#### File updated in place before execution

During testing we identified Windows operating systems may update the Shimcache entry in place instead of creating a new entry at the top. Although not all flows that lead to this were not identified, we identified this was possible to replicate following the below specific steps. This can create timestamp detection when a file is updated in-place:

1. A file gets scanned but not executed (gets inserted to Shimcache)
2. That file is later updated, replaced with a newer version (file last modified time updated)
3. The file gets executed right after (timestamp gets updated in-place in Shimcache & gets inserted to Amcache at the same time)
4. The timestamps in the shimcache and amcache are now near each other and a false detection gets produced, since the shimcache entry was inserted before the timestamps

#### File updated at the same time as the amcache-updating scheduled task runs

The scheduled task `Microsoft Compatibility Appraiser` runs daily and scans the user's Desktop, `C:\Program Files`, and `C:\Program Files (x86)` folders for `.exe` files. If it finds executables that are not present in the amcache, it creates a new entry for them.

The following steps could cause a near timestamp pair that would not match shimcache insertion:

1. File gets inserted to the shimcache (scan/execution)
2. File gets updated (file modified ts updated) at the same time as the task `Microsoft Compatibility Appraiser` runs
3. Shimcache entry timestamp gets updated in-place and a new entry gets inserted to the amcache at the same time
4. The timestamps in the Shimcache and Amcache are now near each other, even if the Shimcache insertion happened earlier

This would most likely produce a maximal error of one day, since the task `Microsoft Compatibility Appraiser` is set to run daily.

T3 – Shimcache Amcache timestamp range matching caveats
-------------------------------------------------------

### Wide time ranges may cause inaccuracies

The wider the time ranges are, the higher the possibility of getting inaccurate Shimcache Amcache match in a time range.

An extreme example would be where there is only one time range that spans the entirety of the Shimcache. In this example there are only two entries in the timeline with a determined timestamp: one at the bottom and one at the top. Now every Shimcache entry between these two entries is in this same time range. If there is an Amcache entry with a matching file path, it is very likely that the Amcache timestamp matches this time range, since it spans a very long time. This means that even if the Shimcache insertion happened during a completely different time than the Amcache insertion, the Amcache timestamp still gets interpreted as the Shimcache insertion time. If there are multiple Shimcache entries all these entries will be matched to Amcache timestamp as the Shimcache insertion time. This may lead to false timestamps and produce an out-of-order timeline with invalid time ranges.

### Out of order timestamps

There is a possibility that some of the timestamps inferred with this technique might produce out of order timestamps on the timeline. This is due to the fact that the `amcache key update timestamp` might have occurred at a slightly different time than the Shimcache insertion. This is mostly a problem with Shimcache entries that were inserted in a burst during a short time frame.

Footer
------

© 2026 GitHub, Inc.

### Footer navigation

* [Terms](https://docs.github.com/site-policy/github-terms/github-terms-of-service)
* [Privacy](https://docs.github.com/site-policy/privacy-policies/github-privacy-statement)
* [Security](https://github.com/security)
* [Status](https://www.githubstatus.com/)
* [Community](https://github.community/)
* [Docs](https://docs.github.com/)
* [Contact](https://support.github.com?tags=dotcom-footer)
* Manage cookies
* Do not share my personal information

You can’t perform that action at this time.