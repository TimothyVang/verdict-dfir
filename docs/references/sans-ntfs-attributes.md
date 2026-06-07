---
source_url: https://www.sans.org/blog/ntfs-attributes-part-one
retrieved: 2026-06-06
fetched_with: scrapling extract get --ai-targeted
trust: UNTRUSTED third-party content captured for DFIR claim substantiation; verify against the live source before relying. Copyright remains with the original publisher.
---

> Source: https://www.sans.org/blog/ntfs-attributes-part-one
> Retrieved 2026-06-06 via Scrapling (get).

---

* Skip to main content
* Go to search
* Go to footer

[Log In](/account/login)

[Join - It's Free](/account/create)

Search

Search

TrainingLearning PathsFree ResourcesFor Organizations

Back[Training](/cyber-security-training-overview)

[Courses

Build cyber prowess with training from renowned experts](/cybersecurity-courses)

[Ways to Train

Multiple training options to best fit your schedule and preferred learning style](/cyber-security-training-formats)

[Cyber Ranges

Hands-on training to keep you at the top of your game](/cyber-ranges)

[Training Events & Summits

Expert-led training at locations around the world](/cyber-security-training-events)

[Certifications

Demonstrate cybersecurity expertise with GIAC certifications](/cyber-security-certifications)

[Free Training Events

Upcoming workshops, webinars and local events](/free-cybersecurity-events)

[Workforce Security and Risk Training

Harden enterprise security with end-user and role-based training](/for-organizations/workforce)

[Meet Our Instructors

Train with world-class cybersecurity experts who bring real-world expertise to class.](/instructors)

Featured Course [View All Courses](/cyber-security-courses)

### SEC595: Applied Data Science and AI/Machine Learning for Cybersecurity Professionals

SEC595Cyber Defense, Artificial Intelligence

![SEC595: Applied Data Science and AI/Machine Learning for Cybersecurity Professionals](https://images.contentstack.io/v3/assets/bltabe50a4554f8e97f/blta744d1449d56747e/68cc24727ca471dde41357dd/course-cards_cyber-defense_SEC595_1514x792.png?width=3840&quality=75&format=webp)

[View course details](/cyber-security-courses/applied-data-science-machine-learning)[Register](/cyber-security-courses/applied-data-science-machine-learning#schedule-pricing)

Get a Free Hour of SANS Training

Experience SANS training through course previews.

[Learn More](/course-preview)

Back[Learning Paths](/learning-paths)

[By Focus Area

Chart your path to job-specific training courses](/cybersecurity-focus-areas)

[New to Cyber

Give your cybersecurity career the right foundation for success](/mlp/new-to-cyber)

[By Job Role

Find the courses and certifications that align with our current or desired role](/job-roles)

[Leadership

Training designed to help security leaders reduce organizational risk](/cybersecurity-focus-areas/leadership)

[By Skills Framework or Directive

Explore how SANS courses align with leading cybersecurity skills frameworks including NICE, ECSF and DoD 8140](/frameworks-and-directives)

[Degree and Certificate Programs

Gain the skills, certifications, and confidence to launch or advance your cybersecurity career.](https://www.sans.edu/)

[By Skills Roadmap

Find the right training path based on critical skills](/cyber-security-skills-roadmap)

Featured[View all Focus Areas](/cybersecurity-focus-areas)

[NEW - AI Security Training](/cybersecurity-focus-areas/ai)

Can't find what you are looking for?

Let us help.

[Contact us](/about/contact)

Back[Free Resources](/security-resources)

Watch & Listen[Webinars](/webcasts)[Summit Presentations](/presentations)[Podcasts & Live Streams](/podcasts)[Overview](/security-resources/watch-and-listen)Read[Blog](/blog)[Newsletters](/newsletters)[Internet Storm Center](https://isc.sans.edu/)[Overview](/security-resources/read)Download[Open Source Tools](/tools)[Posters & Cheat Sheets](/posters)[Policy Templates](/information-security-policy)[White Papers](/white-papers)[Overview](/security-resources/download)

[SANS Community Benefits

Connect, learn, and share with other cybersecurity professionals](/member-benefits)

[Customer Case Studies

Discover how organizations and individual cyber practitioners use SANS training and GIAC certifications](/customer-reviews)

[AI Risk & Readiness

Explore expert-driven guidance, training, and tools to help defend against AI-powered threats and adopt AI securely](/artificial-intelligence)

Join the SANS Community

Become a member for instant access to our free resources.

[Sign Up](/member-benefits)

Back[For Organizations](/for-organizations)

Team Development[Why Partner with SANS](/for-organizations/team-development/why-partner-with-sans)[Group Purchases](/for-organizations/team-development/group-purchasing)[Skills & Talent Assessments](/for-organizations/team-development/cybersecurity-assessments)[Private & Custom Training Programs](/for-organizations/team-development/private-training)[Overview](/for-organizations/team-development)Leadership Development[Management Courses & Accreditation](/cyber-security-courses?refinementList%5Bfacets.focusArea%5D%5B0%5D=Cybersecurity%20Leadership)[Cyber Crisis Exercises](/cyber-ranges/cyber-crisis-exercises)[SANS Cyber Leaders Network](/for-organizations/cyber-leaders-network)[Overview](/cybersecurity-focus-areas/leadership)Workforce Security & Risk[Security Awareness Training](/for-organizations/workforce/security-awareness-training)[Compliance Training](/for-organizations/workforce/compliance-training)[Risk Management](/for-organizations/workforce/risk-management)[Services](/for-organizations/workforce/services)[Resources](/for-organizations/workforce/resources)[Overview](/for-organizations/workforce)

[Public Sector

Mission-focused cybersecurity training for government, defense, and education](/for-organizations/public-sector)

[Partnerships

Explore industry-specific programming and customized training solutions](/partnerships)

[Sponsorship Opportunities

Sponsor a SANS event or research paper](/sponsorship)

Interested in developing a training plan to fit your organization’s needs?

We're here to help.

[Contact Us](/about/contact)

[Group Purchasing](/about/contact#connect-with-a-training-advisor)

[Log In](/account/login)

[Join - It's Free](/account/create)

Menu

Search

Search

[Group Purchasing](/about/contact#connect-with-a-training-advisor)

1. [Blog](/blog)
2. NTFS: Attributes Part One

[Previous level](/blog)

NTFS: Attributes Part One
=========================

Dec 24 2009

Authored by

In [the previous post in this series](https://blogs.sans.org/computer-forensics/2009/12/18/ntfs-an-introduction/) on [NTFS](http://en.wikipedia.org/wiki/NTFS) file systems, we were just dipping our feet in the complicated waters by examining the output of [fsstat](http://www.sleuthkit.org/sleuthkit/man/fsstat.html). Let's pick up where we left off. Below is the $AttrDef Attribute Values section of fsstat's output from the previous post:

```
$AttrDef Attribute Values:
$STANDARD_INFORMATION (16) Size: 48-72 Flags: Resident
$ATTRIBUTE_LIST (32) Size: No Limit Flags: Non-resident
$FILE_NAME (48) Size: 68-578 Flags: Resident,Index
$OBJECT_ID (64) Size: 0-256 Flags: Resident
$SECURITY_DESCRIPTOR (80) Size: No Limit Flags: Non-resident
$VOLUME_NAME (96) Size: 2-256 Flags: Resident
$VOLUME_INFORMATION (112) Size: 12-12 Flags: Resident
$DATA (128) Size: No Limit Flags:
$INDEX_ROOT (144) Size: No Limit Flags: Resident
$INDEX_ALLOCATION (160) Size: No Limit Flags: Non-resident
$BITMAP (176) Size: No Limit Flags: Non-resident
$REPARSE_POINT (192) Size: 0-16384 Flags: Non-resident
$EA_INFORMATION (208) Size: 8-8 Flags: Resident
$EA (224) Size: 0-65536 Flags:
$LOGGED_UTILITY_STREAM (256) Size: 0-65536 Flags: Non-resident
```

Each line of output in this section gives the name of an NTFS attribute followed by the attribute's numeric ID in parentheses. Following the attribute's numeric ID, is an indicator of that attribute's minimum and maximum size limits in bytes, if there are any and finally, we are told if the attribute is resident (contained within the MFT entry) or non-resident. Details for each attribute come from one of NTFS' hidden system files, $AttrDef. $AttrDef is made up of multiple 160 byte records, one for each attribute. Each record contains the attribute's name (see the green highlight in Figure 1), numeric ID (pink highlight), flags (a four byte value at byte offset 140), minimum size (blue highlight), a maximum size (yellow highlight). If an attribute has no size limitations, the minimum size will be set to 0 and the maximum will have all bits set to 1. There are additional fields in each attribute record, see Brian Carrier's [File System Forensic Analysis](http://www.digital-evidence.org/fsfa/index.html) for complete details of the data structures contained in $AttrDef.

As an experiment, I opened the $AttrDef file in a hex editor and changed the $STANDARD\_INFORMATION attribute's name. The name change was reflected in the output of various Sleuthkit utilities. What, your NTFS file system doesn't have the Rob\_Lee\_Forensicator attribute?

Figure 1: Here the $STANDARD\_INFORMATION attribute has been renamed (see green highlight)

So $AttrDef contains attribute definitions. What is the purpose of each attribute? $STANDARD\_INFORMATION contains a number of forensically interesting bits, including file creation time, metadata change time, data modification time, last accessed time, a flag value that can describe various properties of the file, file owner information, a security ID value that is used to map the file to applicable access controls. Complete details can be found in Carrier's File System Forensic Analysis, pages 316-318 and 359-362.

The $ATTRIBUTE\_LIST attribute is used to indicate where other attributes can be found for the given MFT entry, see Carrier pages 320 - 321 and 365 - 367. $ATTRIBUTE\_LIST is only found in MFT entries that have attributes that won't fit in a single MFT entry. Recall that every file on the file system will have at least one MFT entry and that MFT entries are only 1024 bytes in length. If a file has more attributes than can fit in a single MFT entry, additional MFT entries can be linked to from the base MFT.

Next we have the $FILE\_NAME attribute. Obviously the name of the file will be found here, this attribute also contains the same time stamps as the $STANDARD\_INFORMATION attribute, though according to Carrier, they are less reliable. We will spend more time examining the $FILE\_NAME attribute in future posts.

In addition to the file name, files *may* have a 128-bit Globally Unique Identifier (GUID) or $OBJECT\_ID attribute that can be used to access the file. This attribute may be used to locate files even if the file's name has been changed, though on two NTFS file systems I examined in writing this post, no $OBJECT\_IDs were found for any file.

Following the $OBJECT\_ID attribute, comes the $SECURITY\_DESCRIPTOR attribute, an artifact of previous versions of NTFS kept for backwards compatibility. For versions of NTFS prior to 3.0, this attribute contains the access control policy for the file. After 3.0, access control information is stored in a hidden system file called $Security because many files on the file system will use the same access control policy. Storing those policies in one file allows multiple files to point to the same policy entry, conserving disk space.

$VOLUME\_NAME, attribute ID 96 contains the name of the volume. Attribute ID 112, $VOLUME\_INFORMATION contains the file system version information in addition to flags such as the dirty flag, that may indicate that the volume was unmounted improperly, or imaged while mounted or that chkdsk may need to be run on the file system. See the screen shot below for an example hex dump of the $VOLUME\_INFORMATION attribute as found assigned to the hidden system file $Volume.

Figure 2: Hidden system file $Volume and related attributes

Note the use of istat to dump the metadata information for the $Volume file and the use of [icat](http://www.sleuthkit.org/sleuthkit/man/icat.html) to dump the specific contents of the $VOLUME\_NAME and $VOLUME\_INFORMATION attributes using the type IDs for those attributes. More details about $VOLUME\_INFORMATION's Flags field, as well as a comprehensive guide to NTFS can be found at <http://www.scribd.com/doc/2187280/NTFS-Documentation>, a document written by Richard Russon and Yuval Fledel.

After the volume related attributes, we have the $DATA attribute that contains the actual data for our file. Note that for small files, around 700K or less, this attribute may be resident, meaning that the actual data contained in the file will be stored within the [MFT](http://msdn.microsoft.com/en-us/library/aa365230(VS.85).aspx) entry for the file. In a future post, we'll take a look at Alternate Data Streams and the $DATA attribute.

We've made it through just over half the attributes and this post is getting long, so let's call it a day and in the next post in the series, we'll finish our introduction.

#### **Follow up 12/30/2009:**

Reader Harry Parsonage wrote me offline, asking about my comment that I had no files with the $OBJECT\_ID attribute assigned. He found this odd and wanted to know more about the file systems I was working with. The file systems I searched for $OBJECT\_IDs were both created for this series of posts. One is an empty file system with only the system files that are created when a newly formatted file system is created. The other, is the same file system with a few thousand zero length files created via shell script on a Linux system where the NTFS partition was mounted.

I did mount up a file system that I am working for a case and did find numerous files with the $OBJECT\_ID attribute set.

Parsonage added more useful information to the exchange and I wanted to post it here:

*"OK it sounded odd, I believe that the file system only allocates an ObjectID to a file as part of the link tracking process. So a file will get an ObjectID when it is accessed via the File Open/Save As dialog or when it is executed in Windows Explorer. If there has been no activity on the system and there have been no files created or opened that would have a link file associated with them then I don't believe there will be any ObjectIDs."*

Great info and it gives us something to test in a future post. Thanks Harry for the contribution, which brings up another thing I always love to rant about. So much of what we know in the forensics community comes from experimentation and the open exchange of little discoveries that experimentation leads to. This is a huge field and no one knows everything, though clearly some know more than others and many know more than me. Through the application of the scientific method, we can expand what we know.

*Dave Hull, GCFA, GCIH, GREM, CISSP, is founder of Trusted Signal and describes his working life as "on the Venns" of incident response, digital investigations and web application security. He'll be teaching SANS Security 508: Computer Forensics, Investigation and Response in South Lake Tahoe, CA from January 25 through January 30.*

Get Curated News, Vulnerabilities, and Essential Security Awareness Tips
------------------------------------------------------------------------

Subscribe to Newsletter

The Highest Standard in Cybersecurity Education Since 1989
----------------------------------------------------------

### Company

### Help & Support

### Training Programs

### Get Involved

[Privacy Policy](/legal/privacy)[Terms and Conditions](/legal/terms-conditions)[Do Not Sell/Share My Personal Information](/legal/do-not-share-sell)[Cookie Notice](/legal/cookie-notice)

© 2026 The Escal Institute of Advanced Technologies, Inc. d/b/a SANS Institute.Our [Terms and Conditions](/legal/terms-conditions) detail our trademark and copyright rights. Any unauthorized use is expressly prohibited.