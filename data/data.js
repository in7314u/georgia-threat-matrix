/*
  Georgian Threat Matrix - site content.
  Everything the site shows comes from this file. To add content, append to
  the arrays below and commit; no build step is needed.

  actors    one entry per threat actor; mitreDesc is a short summary of the group's MITRE ATT&CK entry
  sectors   columns of the matrix on the home page
  reports   a source document plus the Georgia-related findings taken from it
  timeline  dated events, each pointing back at a report
*/
window.GTM = {
  repo: "https://github.com/in7314u/Georgian-Threat-Matrix",
  contact: { email: "balefulshadow9@proton.me", x: "balefulshadowv9" },

  sectors: [
    { id: "gov", name: "Government" },
    { id: "def", name: "Defence" },
    { id: "mia", name: "Internal affairs" },
    { id: "parl", name: "Parliament" },
    { id: "media", name: "Media" },
    { id: "priv", name: "Private sector & NGOs" }
  ],

  /* MITRE ATT&CK mapping. techniqueUse lists what a source says was done against Georgian targets:
     actor id (empty for unattributed), technique id, the evidence in one sentence, and the report it comes from. */
  tactics: [
    { id: "recon", name: "Reconnaissance" },
    { id: "resource", name: "Resource Development" },
    { id: "initial", name: "Initial Access" },
    { id: "execution", name: "Execution" },
    { id: "persistence", name: "Persistence" },
    { id: "credential", name: "Credential Access" },
    { id: "discovery", name: "Discovery" },
    { id: "collection", name: "Collection" },
    { id: "c2", name: "Command and Control" },
    { id: "exfil", name: "Exfiltration" },
    { id: "impact", name: "Impact" }
  ],
  techniques: {
    "T1595": { name: "Active Scanning", tactic: "recon" },
    "T1585.002": { name: "Establish Accounts: Email Accounts", tactic: "resource" },
    "T1566": { name: "Phishing", tactic: "initial" },
    "T1566.001": { name: "Spearphishing Attachment", tactic: "initial" },
    "T1189": { name: "Drive-by Compromise", tactic: "initial" },
    "T1190": { name: "Exploit Public-Facing Application", tactic: "initial" },
    "T1204.002": { name: "User Execution: Malicious File", tactic: "execution" },
    "T1059.005": { name: "Command and Scripting Interpreter: Visual Basic", tactic: "execution" },
    "T1059.001": { name: "Command and Scripting Interpreter: PowerShell", tactic: "execution" },
    "T1546.015": { name: "Component Object Model Hijacking", tactic: "persistence" },
    "T1003.001": { name: "OS Credential Dumping: LSASS Memory", tactic: "credential" },
    "T1003.003": { name: "OS Credential Dumping: NTDS", tactic: "credential" },
    "T1082": { name: "System Information Discovery", tactic: "discovery" },
    "T1005": { name: "Data from Local System", tactic: "collection" },
    "T1056.001": { name: "Input Capture: Keylogging", tactic: "collection" },
    "T1123": { name: "Audio Capture", tactic: "collection" },
    "T1125": { name: "Video Capture", tactic: "collection" },
    "T1071.003": { name: "Application Layer Protocol: Mail Protocols", tactic: "c2" },
    "T1008": { name: "Fallback Channels", tactic: "c2" },
    "T1090": { name: "Proxy", tactic: "c2" },
    "T1572": { name: "Protocol Tunneling", tactic: "c2" },
    "T1219": { name: "Remote Access Tools", tactic: "c2" },
    "T1048": { name: "Exfiltration Over Alternative Protocol", tactic: "exfil" },
    "T1491.002": { name: "Defacement: External Defacement", tactic: "impact" },
    "T1498": { name: "Network Denial of Service", tactic: "impact" }
  },
  techniqueUse: [
    { actor: "apt29", technique: "T1566.001", report: "dukes",
      basis: "A CosmicDuke campaign used an attachment with a Georgian-language file name about NATO and the Black Sea." },
    { actor: "apt29", technique: "T1204.002", report: "dukes",
      basis: "The CosmicDuke campaign depended on the target opening the attached document." },
    { actor: "apt28", technique: "T1566.001", report: "fireeye-apt28-window",
      basis: "Lure documents written in Georgian, including a weaponized Excel file, were aimed at the Ministry of Internal Affairs and the Ministry of Defense." },
    { actor: "apt28", technique: "T1204.002", report: "fireeye-apt28-window",
      basis: "Opening the lure showed a decoy, such as a list of driver's licence numbers, while malware installed in the background." },
    { actor: "apt28", technique: "T1082", report: "fireeye-apt28-window",
      basis: "The backdoor emailed out a file of system reconnaissance information from the infected machine." },
    { actor: "apt28", technique: "T1056.001", report: "fireeye-apt28-window",
      basis: "A CHOPSTICK variant tied to the Georgian campaign collected keystroke logs." },
    { actor: "apt28", technique: "T1005", report: "fireeye-apt28-window",
      basis: "The same CHOPSTICK variant gathered Microsoft Office documents and PGP files from the machine." },
    { actor: "apt28", technique: "T1071.003", report: "fireeye-apt28-window",
      basis: "The backdoor connected to a Georgian Ministry of Internal Affairs mail server and communicated through ministry email addresses." },
    { actor: "apt28", technique: "T1048", report: "fireeye-case-study",
      basis: "Collected data left by SMTP as an email attachment; EVILTOSS used a file named detaluri.dat." },
    { actor: "sandworm", technique: "T1585.002", report: "doj-gru-indictment",
      basis: "In January 2018 an officer created an email account with a username imitating a Georgian media outlet." },
    { actor: "sandworm", technique: "T1566.001", report: "doj-gru-indictment",
      basis: "Eight spearphishing emails with a malware-laced attachment went to 68 addresses at that media outlet." },
    { actor: "sandworm", technique: "T1595", report: "doj-gru-indictment",
      basis: "On 31 July and 1 August 2019 an officer ran technical reconnaissance against the Parliament of Georgia's internet domain." },
    { actor: "sandworm", technique: "T1491.002", report: "doj-gru-indictment",
      basis: "On 28 October 2019 about 15,000 websites were defaced with an image of a former president." },
    { actor: "muddywater", technique: "T1204.002", report: "unit42-muddywater",
      basis: "The 2017 campaign whose target list includes Georgia relied on malicious Word documents. This describes the campaign as a whole; the source gives no Georgia-specific detail." },
    { actor: "muddywater", technique: "T1059.005", report: "unit42-muddywater",
      basis: "Those documents ran macros when opened. Campaign-wide, not specific to Georgia." },
    { actor: "uac-0056", technique: "T1566", report: "unit42-outsteel-saintbot",
      basis: "Researchers describe the March 2021 attacks on Georgian targets as spear phishing; the exact delivery route is not confirmed." },
    { actor: "uac-0056", technique: "T1204.002", report: "unit42-outsteel-saintbot",
      basis: "A Zip archive held two malicious files beside a decoy letter from Georgia's health ministry." },
    { actor: "lorec53", technique: "T1566.001", report: "nsfocus-lorec53",
      basis: "Phishing documents written in Georgian and themed on current politics were sent to chosen government victims." },
    { actor: "lorec53", technique: "T1204.002", report: "nsfocus-lorec53",
      basis: "The documents showed unreadable text to push the reader into enabling editing." },
    { actor: "lorec53", technique: "T1059.005", report: "nsfocus-lorec53",
      basis: "Enabling editing ran the malicious macros inside the documents." },
    { actor: "lorec53", technique: "T1005", report: "nsfocus-lorec53",
      basis: "The macros delivered a trojan built to steal documents from the victim's computer." },
    { actor: "georbot", technique: "T1189", report: "cert-georgia-georbot",
      basis: "Visitors were infected through compromised Georgian news sites, on pages about NATO and US-Georgian topics." },
    { actor: "georbot", technique: "T1005", report: "eset-georbot",
      basis: "The malware stole documents and certificates from infected computers." },
    { actor: "georbot", technique: "T1123", report: "eset-georbot",
      basis: "It could record audio." },
    { actor: "georbot", technique: "T1125", report: "eset-georbot",
      basis: "It could record video; the operator's own webcam was later used against him." },
    { actor: "georbot", technique: "T1008", report: "eset-georbot",
      basis: "When its command server was unreachable, the bot fetched instructions from a page planted on a Georgian government-hosted system." },
    { actor: "winter-vivern", technique: "T1190", report: "rf-tag-70",
      basis: "The group exploited cross-site scripting flaws in Roundcube webmail servers, including the Ministry of Defence mail server." },
    { actor: "curly-comrades", technique: "T1546.015", report: "bitdefender-curly-comrades",
      basis: "The MucorAgent backdoor persisted by hijacking a COM object identifier." },
    { actor: "curly-comrades", technique: "T1059.001", report: "bitdefender-curly-comrades",
      basis: "MucorAgent ran AES-encrypted PowerShell scripts." },
    { actor: "curly-comrades", technique: "T1003.001", report: "bitdefender-curly-comrades",
      basis: "The intruders tried to dump LSASS memory to recover the credentials of logged-in users." },
    { actor: "curly-comrades", technique: "T1003.003", report: "bitdefender-curly-comrades",
      basis: "They repeatedly tried to extract the NTDS database from domain controllers." },
    { actor: "curly-comrades", technique: "T1090", report: "bitdefender-curly-comrades",
      basis: "Resocks and a SOCKS5 server relayed traffic into the internal network." },
    { actor: "curly-comrades", technique: "T1572", report: "bitdefender-curly-comrades",
      basis: "SSH port forwarding and Stunnel wrapped that traffic in encrypted tunnels." },
    { actor: "curly-comrades", technique: "T1219", report: "bitdefender-curly-comrades",
      basis: "The legitimate Remote Utilities tool gave them additional remote access." },
    { actor: "", technique: "T1498", report: "nyt-before-the-gunfire",
      basis: "Denial-of-service floods hit Georgian government websites from 20 July 2008 and through the August war." },
    { actor: "", technique: "T1498", report: "us-ccu-2008",
      basis: "The 7 to 16 August 2008 attacks were carried out by civilians and criminal groups, with signs of coordination with the Russian military." }
  ],

  actors: [
    {
      id: "apt29",
      mitreDesc: "Attributed to Russia's Foreign Intelligence Service (SVR) and active since at least 2008. It mainly targets government networks in Europe and NATO member countries, along with research institutes and think tanks. Known operations include the 2015 compromise of the US Democratic National Committee and the SolarWinds supply-chain attack.",
      name: "APT29",
      mitre: "G0016",
      origin: "Russia",
      sponsor: "Foreign Intelligence Service (SVR)",
      aliases: ["Cozy Bear", "The Dukes", "CozyDuke", "NOBELIUM", "Midnight Blizzard", "IRON RITUAL", "IRON HEMLOCK", "NobleBaron", "Dark Halo", "UNC2452", "UNC3524", "YTTRIUM", "SolarStorm", "Blue Kitsune", "ATK7"],
      summary: "Espionage campaigns against the Ministry of Defence and the Georgian Information Centre on NATO from 2009, using PinchDuke and later CosmicDuke.",
      sectors: { gov: "documented", def: "documented" }
    },
    {
      id: "apt28",
      mitreDesc: "Attributed to GRU Unit 26165 (the 85th Main Special Service Center) and active since at least 2004. It compromised the Clinton campaign and the Democratic National Committee in 2016. Five of its officers were indicted by the US in 2018 for operations against anti-doping bodies, a nuclear facility and the chemical weapons watchdog.",
      name: "APT28",
      mitre: "G0007",
      origin: "Russia",
      sponsor: "GRU Unit 26165",
      aliases: ["Fancy Bear", "Pawn Storm", "Sofacy Group", "Sednit"],
      summary: "Georgian-language lures aimed at the Ministry of Internal Affairs and the Ministry of Defence, and linked to the targeting of the Georgian military during the 2008 war.",
      sectors: { def: "documented", mia: "documented" }
    },
    {
      id: "sandworm",
      mitreDesc: "A destructive group attributed to GRU Unit 74455, active since at least 2009. It is behind the 2015 and 2016 attacks on Ukraine's power grid, the 2017 NotPetya attack and the 2018 Olympic Destroyer attack. MITRE's entry also lists its attacks on Georgia in 2018 and 2019.",
      name: "Sandworm",
      mitre: "G0034",
      origin: "Russia",
      sponsor: "GRU Unit 74455",
      aliases: ["Sandworm Team", "Unit 74455"],
      summary: "Spearphishing of a Georgian media outlet in 2018, reconnaissance of Parliament in 2019, and the October 2019 defacement of roughly 15,000 websites.",
      sectors: { gov: "documented", parl: "documented", media: "documented", priv: "documented" }
    },
    {
      id: "muddywater",
      mitreDesc: "A cyber-espionage group attributed to Iran's Ministry of Intelligence and Security, active since at least 2017. It targets government bodies and telecommunications, finance, defence, local government and energy companies, mainly in the Middle East but also in Asia, Africa, Europe and North America.",
      name: "MuddyWater",
      mitre: "G0069",
      origin: "Iran",
      sponsor: "Ministry of Intelligence and Security (MOIS)",
      aliases: [],
      summary: "Georgia appears in the list of countries targeted, or suspected to be targeted, in the group's 2017 activity.",
      sectors: {},
      sectorNote: "Country-level mention only"
    },
    {
      id: "uac-0056",
      mitreDesc: "Tracked by MITRE as Saint Bear, a Russian-nexus group active since early 2021 that mainly targets organisations in Ukraine and Georgia. MITRE treats it as separate from Ember Bear, with which it was earlier confused.",
      name: "UAC-0056",
      mitre: "G1031",
      origin: "Russia",
      sponsor: "",
      aliases: ["Saint Bear", "TA471", "Storm-0587", "Lorec53"],
      related: ["lorec53"],
      note: "MITRE ATT&CK tracks this activity as Saint Bear (G1031) and says it mainly targets Ukraine and Georgia. Some vendors merge it with Ember Bear (G1003, GRU Unit 29155); MITRE treats the two as separate clusters.",
      summary: "A March 2021 campaign against targets in Georgia using Bitcoin and COVID themes, with a decoy letter from the Ministry of Labour, Health and Social Affairs.",
      sectors: { gov: "suggested" }
    },
    {
      id: "lorec53",
      mitreDesc: "Tracked by MITRE as Saint Bear, a Russian-nexus group active since early 2021 that mainly targets organisations in Ukraine and Georgia. MITRE treats it as separate from Ember Bear, with which it was earlier confused.",
      name: "Lorec53",
      mitre: "G1031",
      origin: "Russia",
      sponsor: "",
      aliases: ["Saint Bear", "LorecBear", "UAC-0056"],
      related: ["uac-0056"],
      note: "Lorec53 is NSFOCUS's name for the activity MITRE ATT&CK tracks as Saint Bear (G1031), the same group as UAC-0056.",
      summary: "Georgian-language phishing documents built on current political topics, delivering a document-stealing trojan to government targets in 2021.",
      sectors: { gov: "documented" }
    },
    {
      id: "georbot",
      mitreDesc: "",
      name: "Georbot",
      mitre: "",
      origin: "Russia (per CERT-Georgia)",
      sponsor: "",
      aliases: ["Win32/Georbot"],
      note: "Georbot is the name of the malware and botnet; no vendor group name exists. ESET did not attribute it to any state. The link to Russian security agencies is the Georgian government's own assessment.",
      summary: "An information-stealing botnet found in 2011-2012 on computers in Georgian ministries, parliament, banks and NGOs, spread through compromised Georgian news sites.",
      sectors: { gov: "documented", parl: "documented", priv: "documented" }
    },
    {
      id: "winter-vivern",
      mitreDesc: "A group tied to Russian and Belarusian interests, active since at least 2020. It mainly targets government and non-governmental organisations in Europe, with occasional victims in India and the United States.",
      name: "Winter Vivern",
      mitre: "G1035",
      origin: "Russia / Belarus",
      sponsor: "",
      aliases: ["TAG-70", "TA473", "UAC-0114"],
      note: "Recorded Future assesses the group as likely operating on behalf of Belarus and Russia. No specific agency has been named.",
      summary: "Exploited Roundcube webmail flaws in late 2023 against more than 80 organisations, mainly in Georgia, Poland and Ukraine, including the Georgian Ministry of Defence mail server.",
      sectors: { gov: "documented", def: "documented" }
    },
    {
      id: "curly-comrades",
      mitreDesc: "",
      name: "Curly COMrades",
      mitre: "",
      origin: "Russia-aligned",
      sponsor: "",
      aliases: [],
      note: "Bitdefender found insufficient evidence to tie the activity to a known group and describes it only as supporting Russian interests.",
      summary: "Long-term access and credential theft against judicial and government bodies in Georgia, tracked by Bitdefender since mid-2024.",
      sectors: { gov: "documented" }
    }
  ],

  reports: [
    {
      id: "dukes",
      actors: ["apt29"],
      title: "The Dukes: 7 Years of Russian Cyberespionage",
      publisher: "F-Secure",
      year: 2015,
      links: [
        { label: "F-Secure whitepaper (PDF)", url: "https://blog-assets.f-secure.com/wp-content/uploads/2020/03/18122307/F-Secure_Dukes_Whitepaper.pdf", archived: true },
        { label: "WithSecure Labs mirror (PDF, Web Archive)", url: "https://web.archive.org/web/20241120124207/https://labs.withsecure.com/content/dam/labs/docs/dukes-whitepaper.pdf", archived: true }
      ],
      findings: [
        "PinchDuke samples discovered from 2009, the targets of the Dukes group during that year included organizations such as the Ministry of Defense of Georgia",
        "Targeting what was then known as the Georgian Information Centre on NATO",
        "The second notable cluster comprises of two campaigns that were possibly aimed at gathering information on Georgia-NATO relations. The first of these runs used the campaign identifier “natoinfo_ge”, an apparent reference to the www.natoinfo.ge website belonging to a Georgian political body that has since been renamed “Information Centre on NATO and EU”. Although the campaign identifier itself doesn’t contain a date, we believe the campaign to have originated around the 7th of June 2009, which was when the PinchDuke sample in question was compiled. This belief is based on the observation that in all of the other PinchDuke samples we have analyzed, the date of the campaign identifier has been within a day of the compilation date. The second campaign identifier, which we suspect may be related, is “mod_ge_2009_07_03” from a month later and apparently targeting the Ministry of Defense of Georgia.",
        "The spring of 2010 saw continued PinchDuke campaigns against Turkey and Georgia",
        "CosmicDuke campaign was observed presumably targeting Georgian entities since it used an attachment with a Georgian-language name that translates to “NATO consolidates control of the Black Sea.docx”"
      ]
    },
    {
      id: "apt-awareness-review",
      actors: ["apt28"],
      title: "Advanced Persistent Threats (APT): An Awareness Review",
      publisher: "Journal of Economics and Economic Education Research",
      year: 2020,
      links: [
        { label: "Journal article (PDF)", url: "https://www.abacademies.org/articles/Advanced-persistent-threats-apt-an-awareness-review-1533-3604-21-6-202.pdf", archived: true }
      ],
      findings: [
        "APT-28, Attacks against military and government targets in Eastern Europe, including Ukraine and Georgia, as well as campaigns targeting NATO organizations and U.S. defense contractors. Russian groups: Fancy Bear, Pawn Storm, Sofacy Group and Sednit",
        "APT 28 has targeted Ministries of Defense all over Europe and is believed to be the group that targeted the Georgian military during the 2008 Russo-Georgian war"
      ]
    },
    {
      id: "cna-information-confrontation",
      actors: ["apt28"],
      title: "The Role of Russia's Military in Information Confrontation",
      publisher: "CNA",
      year: 2021,
      links: [
        { label: "CNA report (PDF)", url: "https://www.cna.org/reports/2021/06/The-Role-of-Russia%27s-Military-in-Information-Confrontation.pdf", archived: true }
      ],
      findings: [
        "Between 2004 and 2013, APT28-a hacker outfit attributed to the GRU’s Unit 26165-used fake NATO correspondence and imitated pro-Chechen websites to exploit networks to gain intelligence on adversaries. The IP address used to host the “stopgeorgia” website during Russia’s war with Georgia in 2008 belonged to a small company, Steadyhost, that was essentially collocated with a large GRU complex on Khoroshevskoe Highway in Moscow"
      ]
    },
    {
      id: "fireeye-case-study",
      actors: ["apt28"],
      title: "Case Study: APT28 Cybergroup Activity",
      publisher: "FireEye / Security Case Study",
      year: 2014,
      links: [
        { label: "Conference slides (PDF)", url: "https://www.securitycasestudy.pl/wp-content/uploads/2015/05/SCS14%E2%80%93MOstrowski.TPietrzyk.pdf", archived: true }
      ],
      findings: [
        "APT28 likely seeks to collect intelligence about Georgia’s security and political dynamics by targeting officials working for the Ministry of Internal Affairs and the Ministry of Defense.",
        "Names include: Georgian language IT Document for Ministry of Internal Affairs (internal document), John Shinjikashvili (Georgian-Polish-American US General) Questionnaire, Georgian language document about drivers' licenses (internal document)",
        "Those documents used the following malware: SOURFACE, CORESHELL, EVILTOSS",
        "EVILTOSS variants may use the Simple Mail Transfer Protocol (SMTP) to send stolen data in an attachment named “detaluri.dat”"
      ]
    },
    {
      id: "gfsis-massive-cyberattacks",
      actors: ["apt28"],
      title: "Massive Cyberattacks On Georgia Calls For Defense And Resilience",
      publisher: "GFSIS",
      year: null,
      links: [
        { label: "GFSIS article", url: "https://gfsis.org/en/massive-cyberattacks-on-georgia-calls-for-defense-and-resilience/" },
        { label: "Web Archive copy", url: "https://web.archive.org/web/20250425000244/https://gfsis.org/en/massive-cyberattacks-on-georgia-calls-for-defense-and-resilience/" }
      ],
      findings: [
        "APT 28, which is associated with the GRU, Russian military intelligence. According to a report from the respected cybersecurity company FireEye, this group attacked websites of the Georgian Ministry of Internal Affairs and Ministry of Defense. These attacks were advanced, persistent and complex. Hackers penetrated a network via spear-phishing techniques and carried out long-running cyber espionage campaigns."
      ]
    },
    {
      id: "fireeye-apt28-window",
      actors: ["apt28"],
      title: "APT28: A Window into Russia’s Cyber Espionage Operations?",
      publisher: "FireEye",
      year: 2014,
      links: [
        { label: "FireEye report (PDF)", url: "https://cyber-peace.org/wp-content/uploads/2015/06/fireeye-apt28.pdf", archived: true }
      ],
      findings: [
        "Since 2011, APT28 has used lures written in Georgian that are probably intended to target Georgian government agencies or citizens. APT28 is likely seeking information on Georgia’s security and diplomatic postures. Specifically, the group has targeted the Georgian Ministry of Internal Affairs (MIA) and the Ministry of Defense (MOD). We also observed efforts to target a journalist working on issues in the Caucasus and a controversial Chechen news site.",
        "APT28 made at least two specific attempts to target the MIA. In one case, we identified an APT28 lure from mid-2013 that referenced MIA-related topics and employed malware that attempted to disguise its activity as legitimate MIA email traffic. The lure consisted of a weaponized Excel file that presented a decoy document containing a list of Georgian driver’s license numbers. The backdoor attempted to establish a connection to a Georgian MIA mail server and communicate via MIA email addresses ending with “@mia.ge.gov”. Once connected to the mail server, APT28’s backdoor sent an email message using a subject line related to driver’s licenses (in Georgian), and attached a file containing system reconnaissance information. This tactic could allow APT28 to obtain data from the MIA’s network through a less-monitored route, limiting the MIA network security department’s abilities to detect the traffic",
        "In the second example of MIA targeting, an APT28 lure used an information technology-themed decoy document that included references to the Windows domain “MIA Users\\Ortachala…”. This probably referred to the MIA facility in the Ortachala district of Tbilisi, Georgia’s capital city. The decoy document also contains metadata listing “MIA” as the company name and “Beka Nozadze” as an author, a possible reference to a system administrator in Tbilisi. The text of the document purports to provide domain and user group setup information for internal Windows XP and Windows 7 systems. APT28 possibly crafted this document to appear legitimate to all MIA system users and intended to breach the MIA network specifically using the embedded malware.",
        "APT28 also appeared to target Georgia’s MOD along with a U.S. defense contractor that was training the Georgian military. APT28 used a lure document that installed a SOURFACE downloader and contained a listing of birthdays for members of a working group between the Georgian MOD and the U.S. defense contractor. The U.S. contractor was involved in a working group to advise the MOD and Georgian Armed Forces, assess Georgia’s military capabilities, and develop a military training program for the country",
        "One CHOPSTICK v1 variant contained modules and functions for collecting keystroke logs, Microsoft Office documents, and PGP files. The monitoring for new files of interest is performed by a “Directory Observer” module. In one sample this information was intended to be sent via SMTP using a Georgian MIA mail server. It used one of four embedded sender email addresses (@mia.gov.ge) to send files via email to another email address on the same mail server. All information required for the email was hardcoded in the backdoor."
      ]
    },
    {
      id: "stratcom-russia-strategy",
      actors: ["apt28"],
      title: "Russia’s Strategy in Cyberspace",
      publisher: "NATO StratCom COE",
      year: 2021,
      links: [
        { label: "StratCom COE report (PDF)", url: "https://stratcomcoe.org/cuploads/pfiles/Nato-Cyber-Report_11-06-2021-4f4ce.pdf", archived: true }
      ],
      findings: []
    },
    {
      id: "doj-gru-indictment",
      actors: ["sandworm"],
      title: "Six Russian GRU Officers Charged in Connection with Worldwide Deployment of Destructive Malware and Other Disruptive Actions in Cyberspace",
      publisher: "U.S. Department of Justice",
      year: 2020,
      links: [
        { label: "U.S. Embassy statement condemning the attack on Georgia", url: "https://ge.usembassy.gov/the-united-states-condemns-russian-cyber-attack-against-the-country-of-georgia-february-20/" },
        { label: "DOJ press release", url: "https://www.justice.gov/archives/opa/pr/six-russian-gru-officers-charged-connection-worldwide-deployment-destructive-malware-and" },
        { label: "Indictment, W.D. Pennsylvania (PDF)", url: "https://www.justice.gov/archives/opa/press-release/file/1328521/dl", archived: true },
        { label: "Exhibit A (PDF)", url: "https://www.justice.gov/opa/press-release/file/1328541/dl", archived: true }
      ],
      findings: [
        "Anatoliy Sergeyevich Kovalev developed spearphishing techniques and messages used to target employees of a Georgian media entity.",
        "Artem Valeryevich Ochichenko conducted technical reconnaissance of the Parliament of Georgia official domain and attempted to gain unauthorized access to its network.",
        "Listed as victims: “The country of Georgia and Georgian non-government organizations and private companies, including through a spearphishing campaign in and around January 2018 targeting a Georgian media outlet and a cyber attack in and around October 2019 that defaced approximately 15,000 websites and disrupted service to some of these websites”",
        "Defendant Anatoliy Sergeyevich Kovalev was a Russian military intelligence officer assigned to Military Unit 74455. Kovalev sent spearphishing emails targeting a wide variety of entities and individuals, including those associated with French local government entities, political parties, and campaigns; the 2018 Winter Olympics; the DSTL; and a Georgian media entity. Kovalev also engaged in spearphishing campaigns for apparent personal profit, including campaigns targeting large Russian real estate companies, auto dealers, and cryptocurrency miners, as well as cryptocurrency exchanges located outside of Russia.",
        "Defendant Artem Valeryevich Ochichenko served as a Russian military intelligence officer in Military Unit 74455. Ochichenko developed malicious email attachments and sent spearphishing emails containing those attachments to individuals working for the 2018 Winter Olympics' official timekeeping partners and their subsidiaries. Ochichenko was also involved in the Conspirators' targeting of the Georgian government and other Georgian entities in 2019",
        "Similar to their targeting of Ukraine since 2015, the Conspirators engaged in a broad cyber campaign against government and private sector entities in the country of Georgia, including the Parliament of Georgia and a major media outlet, with disruptive and destructive attacks to undermine confidence in and otherwise destabilize Georgia.",
        "For example, on or about January 2018, Kovalev created an email account with a username emulating the name of a Georgian media entity that focuses on news coverage. Shortly thereafter, Kovalev used the account to send eight spearphishing emails with a malware-laced attachment to 68 email addresses hosted at the domain belonging to that same Georgian media entity.",
        "On or about July 31, 2019, and August 1, 2019, Ochichenko conducted technical reconnaissance of the Parliament of Georgia's official internet domain and attempted to gain unauthorized access to its network.",
        "Months later, on or about October 28, 2019, the Conspirators engaged in a wider-ranging cyber attack against a large number of entities in the country of Georgia. This attack targeted websites belonging to Georgian government, non-government, and private sector entities and involved the defacement of approximately 15,000 websites and the disruption of service to some of these websites after the computer systems of a Georgian web hosting provider were compromised. In many cases, the Conspirators replaced website home pages with an image of a former Georgian president, who was known for his efforts to counter Russian influence in Georgia, along with the caption “I'll be back.”"
      ]
    },
    {
      id: "crs-russian-cyber-units",
      actors: ["sandworm"],
      title: "Russian Cyber Units",
      publisher: "Congressional Research Service",
      year: 2022,
      links: [
        { label: "CRS In Focus IF11718", url: "https://www.everycrsreport.com/reports/IF11718.html" }
      ],
      findings: [
        "Unit 74455 appears to have significant offensive cyber capabilities. In October 2020, DOJ indicted members of GRU Unit 74455 for numerous cyberattacks, including the 2017 NotPetya malware attack.",
        "From the report’s background section on the 2008 war, not its Unit 74455 section: Georgia was the victim of a large-scale cyberattack that corresponded with Russian military actions. Analysts identified 54 potential targets (e.g., government, financial, and media outlets), including the National Bank of Georgia, which suspended all electronic operations for 12 days."
      ]
    },
    {
      id: "nksc-ukraine-report",
      actors: ["sandworm"],
      title: "Report on the Russian Use of Offensive Cyber Capabilities in the Course of the Military Aggression in Ukraine",
      publisher: "NKSC (Lithuania)",
      year: null,
      links: [
        { label: "NKSC report (PDF)", url: "https://www.nksc.lt/doc/rkgc/Report_Russian_Use_of_Offensive_Cyber_Capabilities_in_UA.pdf", archived: true },
        { label: "Web Archive copy", url: "https://web.archive.org/web/20250122204603/https://www.nksc.lt/doc/rkgc/Report_Russian_Use_of_Offensive_Cyber_Capabilities_in_UA.pdf" }
      ],
      findings: [
        "Sandworm: a threat group, attributed to GRU’s unit 74455, has been active since at least 2009. In October 2020, the US indicted six GRU Unit 74455 officers associated with Sandworm Team for the following cyber operations: the 2015 and 2016 attacks against Ukrainian electrical companies and government organizations, the 2017 worldwide NotPetya attack, targeting of the 2017 French presidential campaign, the 2018 Olympic Destroyer attack against the Winter Olympic Games, the 2018 operation against the Organisation for the Prohibition of Chemical Weapons, and attacks against the country of Georgia in 2018 and 2019"
      ]
    },
    {
      id: "crs-selected-cyberattacks",
      actors: ["sandworm"],
      title: "Cybersecurity: Selected Cyberattacks, 2012-2024",
      publisher: "Congressional Research Service",
      year: 2024,
      links: [
        { label: "CRS report R46974 (PDF)", url: "https://www.everycrsreport.com/files/2024-12-20_R46974_6d7ac39d358a4079a702011755dd635c1926ccb1.pdf", archived: true }
      ],
      findings: [
        "Sandworm attacked the Ukrainian government and critical infrastructure (BlackEnergy); sought to interfere in the French national elections; conducted the NotPetya attacks against U.S.-based hospitals, shipping companies, and pharmaceutical companies; sought to undermine the PyeongChang Winter Olympics; spear phished investigators of the Novichok poisoning to gain sensitive data; and sought to compromise Georgian government entities."
      ]
    },
    {
      id: "unit42-muddywater",
      actors: ["muddywater"],
      title: "Muddying the Water: Targeted Attacks in the Middle East",
      publisher: "Palo Alto Networks Unit 42",
      year: 2017,
      links: [
        { label: "Unit 42 article", url: "https://unit42.paloaltonetworks.com/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/" }
      ],
      findings: [
        "The activity has been consistent throughout 2017 and, based on our analysis, targets or is suspected to target, entities in a list of countries that includes Georgia."
      ]
    },
    {
      id: "unit42-outsteel-saintbot",
      actors: ["uac-0056"],
      title: "Spear Phishing Attacks Target Organizations in Ukraine, Payloads Include the Document Stealer OutSteel and the Downloader SaintBot",
      publisher: "Palo Alto Networks Unit 42",
      year: 2022,
      links: [
        { label: "Unit 42 article", url: "https://unit42.paloaltonetworks.com/ukraine-targeted-outsteel-saintbot/#march-2021-attacks" }
      ],
      findings: [
        "March 2021: An attack campaign against targets in Georgia using Bitcoin and COVID themes.",
        "According to MalwareBytes research, this threat group carried out an attack campaign in March 2021 on targets in Georgia using Bitcoin and COVID themes. The researchers state that these attacks involve spear phishing, but we do not have telemetry to confirm the targeted organizations, attack vector or the exact dates in which the attacks took place. The Bitcoin-themed attacks are very similar to those seen in later April attacks, as the PDF delivery documents had similar content that references Electrum bitcoin wallets.",
        "The COVID-themed attacks reference a government organization in Georgia, which suggests that the threat group has interests in other countries in the region in addition to Ukraine. The attack involved a Zip archive hosted at bgicovid19[.]com/assets/img/newCOVID-21.zip and contains the two malicious files and one decoy document.",
        "The letter from the Ministry of Labour, Health and Social Affairs of Georgia.pdf document is a decoy, as it contains no malicious content. The decoy content does show a document from the Ministry of Labour, Health and Social Affairs of Georgia, which suggests that the target may have involved an organization in Georgia."
      ]
    },
    {
      id: "nsfocus-lorec53",
      actors: ["lorec53"],
      title: "Lorec53, An Active Russian Hack Group Launched Phishing Attacks Against Georgian Government",
      publisher: "NSFOCUS Security Labs",
      year: 2022,
      links: [
        { label: "NSFOCUS article", url: "https://nsfocusglobal.com/apt-retrospection-lorec53-an-active-russian-hack-group-launched-phishing-attacks-against-georgian-government/" },
        { label: "APT Retrospection (PDF mirror)", url: "https://s3.amazonaws.com/contagio.deependresearch.org/read/Ember_Bear_2022_APT_Retrospection__Lorec53%2C_An_Active_Russian_Hack_Group_Launched_Phishing_Attacks_Against_Georgian_Government.pdf", archived: true }
      ],
      findings: [
        "In July 2021, several phishing documents created in Georgian were discovered by NSFOCUS Security Labs. In these phishing documents, the attackers used current political hotspots in Georgia to create bait and deliver a secret stealing Trojan to specifically targeted victims aiming to steal various documents from their computers. Correlation analysis shows that this phishing campaign and an earlier phishing attack against the Ukrainian government came from the same unknown threat entity, most likely composed of Russian hackers. From April to July of 2021, the group launched several phishing attacks applying a large number of network resources located in Russia. In order to facilitate ongoing tracking, NSFOCUS Security Labs has tentatively dubbed the hacker group Lorec53 by extracting special names from related Trojans.",
        "The phishing documents that appeared in this attack were named 828-ში ცვლილება.doc and დევნილთა 2021-2022 წლების სტრატეგიის სამოქმედო გეგმა.doc.",
        "When დევნილთა 2021-2022 წლების სტრატეგიის სამოქმედო გეგმა.doc is opened, everything except the title is unreadable. The invisible parts of the two documents have no real meaning and are only used to lure the recipient to enable the editing feature of Office. Once this feature is enabled, the malicious macros in the documents are executed."
      ]
    },
    {
      id: "telsy-babadeda",
      actors: ["lorec53", "uac-0056"],
      title: "BabaDeda and LorecCPL downloaders used to run Outsteel against Ukraine",
      publisher: "Telsy",
      year: 2022,
      links: [
        { label: "Telsy report (PDF)", url: "http://contagio.deependresearch.org/read/Nodaria_2022_BabaDeda_and_LorecCPL_downloaders_used_to_run_Outsteel_against_Ukraine_Telsy.pdf", archived: true }
      ],
      findings: []
    },
    {
      id: "contagio-ember-bear",
      actors: ["lorec53", "uac-0056"],
      title: "Malware Arsenal used by Ember Bear (aka UAC-0056, Saint Bear, UNC2589, Lorec53, TA471, Nodaria, Nascent Ursa, LorecBear, Bleeding Bear, and DEV-0586) in attacks targeting Ukraine",
      publisher: "Contagio",
      year: 2023,
      links: [
        { label: "Contagio post", url: "https://contagiodump.blogspot.com/2023/02/malware-arsenal-used-by-ember-bear-aka.html" }
      ],
      findings: []
    },

    /* Added through research. Findings below are summaries, not quotations. */
    { id: "nyt-before-the-gunfire", actors: [], paraphrased: true, title: "Before the Gunfire, Cyberattacks", publisher: "The New York Times (via UNIAN)", year: 2008,
      links: [{ label: "UNIAN reprint", url: "https://www.unian.info/world/137288-before-the-gunfire-cyberattacks.html" }],
      findings: ["Researchers saw denial-of-service traffic aimed at Georgian government websites as early as 20 July 2008, weeks before the war began."] },
    { id: "us-ccu-2008", actors: [], paraphrased: true, title: "Georgian Cyberattacks Traced to Russian Civilians (coverage of the US Cyber Consequences Unit report)", publisher: "MIT Technology Review", year: 2009,
      links: [{ label: "MIT Technology Review", url: "https://www.technologyreview.com/2009/08/18/210438/georgian-cyberattacks-traced-to-russian-civilians/" },
        { label: "CCDCOE cyber law toolkit: Georgia-Russia conflict (2008)", url: "https://cyberlaw.ccdcoe.org/wiki/Georgia-Russia_conflict_(2008)" }],
      findings: ["The US Cyber Consequences Unit analysed attacks that ran from 7 to 16 August 2008 and concluded they were carried out by civilians and criminal groups, with signs of advance coordination with the Russian military.",
        "Only a nine-page summary of the roughly 100-page report was made public."] },
    { id: "eset-georbot", actors: ["georbot"], paraphrased: true, title: "From Georgia With Love: Win32/Georbot information stealing trojan and botnet", publisher: "ESET", year: 2012,
      links: [{ label: "WeLiveSecurity article", url: "https://www.welivesecurity.com/2012/03/21/win32georbot-information-stealing-trojan-botnet-from-georgia-with-love/" }],
      findings: ["Georbot steals documents and certificates, can record audio and video, and searches the local network; ESET found it aimed at Georgian users in particular.",
        "When its command server was unreachable, the bot fetched new instructions from a page planted on a Georgian government-hosted system.",
        "Georgia's Data Exchange Agency and national CERT had known of the botnet since 2011 and worked with ESET. ESET did not attribute it to a state."] },
    { id: "cert-georgia-georbot", actors: ["georbot"], paraphrased: true, title: "Georgia: Russia responsible for Georbot cyber-spy attack (coverage of the CERT-Georgia report)", publisher: "Infosecurity Magazine", year: 2012,
      links: [{ label: "Infosecurity Magazine", url: "https://www.infosecurity-magazine.com/news/georgia-russia-responsible-for-georbot-cyber-spy/" }],
      findings: ["CERT-Georgia reported the malware in ministries, parliament, banks and NGOs, with roughly 300 to 400 infected computers sending documents to servers run by the operator.",
        "Infection came through compromised Georgian news sites, on pages covering NATO and US-Georgian topics.",
        "CERT-Georgia turned the operator's own malware on him, captured his webcam image, and said it had established a link to Russian security agencies."] },
    { id: "kaspersky-miniduke", actors: ["apt29"], paraphrased: true, title: "The MiniDuke Mystery: PDF 0-day Government Spy Assembler 0x29A Micro Backdoor", publisher: "Kaspersky / CrySyS Lab", year: 2013,
      links: [{ label: "Securelist article", url: "https://securelist.com/the-miniduke-mystery-pdf-0-day-government-spy-assembler-0x29a-micro-backdoor/31112/" }],
      findings: ["Command-server logs showed 59 victims in 23 countries, and Georgia is one of the countries listed. MiniDuke is part of the Dukes toolset later attributed to APT29."] },
    { id: "eset-potao", actors: [], paraphrased: true, title: "Operation Potao Express: Analysis of a cyberespionage toolkit", publisher: "ESET", year: 2015,
      links: [{ label: "WeLiveSecurity article", url: "https://www.welivesecurity.com/2015/07/30/operation-potao-express/" }],
      findings: ["ESET describes Potao as targeted espionage malware aimed mostly at Ukraine and at other post-Soviet countries including Russia, Georgia and Belarus. No Georgian victims are named."] },
    { id: "eset-zebrocy", actors: ["apt28"], paraphrased: true, title: "Sednit update: Analysis of Zebrocy", publisher: "ESET", year: 2018,
      links: [{ label: "WeLiveSecurity article", url: "https://www.welivesecurity.com/2018/04/24/sednit-update-analysis-zebrocy/" }],
      findings: ["ESET lists Georgia among 18 countries where it saw victims of Zebrocy, a first-stage tool of the Sednit group (APT28). The targets were embassies, foreign ministries and diplomats."] },
    { id: "uk-condemns-gru-2020", actors: ["sandworm"], paraphrased: true, title: "UK condemns Russia's GRU over Georgia cyber-attacks", publisher: "UK Government / NCSC", year: 2020,
      links: [{ label: "GOV.UK news", url: "https://www.gov.uk/government/news/uk-condemns-russias-gru-over-georgia-cyber-attacks" }],
      findings: ["On 20 February 2020 the UK said its National Cyber Security Centre assessed, with more than 95% confidence, that the GRU was responsible for the 28 October 2019 attacks.",
        "The attacks defaced websites of the Georgian government, courts, NGOs, media and businesses, and interrupted the service of national broadcasters."] },
    { id: "lugar-lab-2020", actors: [], paraphrased: true, title: "Georgia: 'Foreign Intelligence' behind Health Ministry, Lugar Center Cyberattack", publisher: "Civil.ge", year: 2020,
      links: [{ label: "Civil.ge", url: "https://civil.ge/archives/365113" },
        { label: "OC Media", url: "https://oc-media.org/foreign-special-service-hacks-lugar-lab-and-georgian-health-ministry" }],
      findings: ["The Ministry of Internal Affairs said a foreign intelligence service attacked the health ministry's systems on 1 September 2020 to obtain medical and pandemic-management records, including those of the Lugar Center.",
        "Genuine stolen documents were then posted on a foreign website mixed with forged ones. The government did not officially name a country."] },
    { id: "mitre-saint-bear", actors: ["uac-0056", "lorec53"], paraphrased: true, title: "Saint Bear (G1031)", publisher: "MITRE ATT&CK", year: null,
      links: [{ label: "MITRE ATT&CK group page", url: "https://attack.mitre.org/groups/G1031/" }],
      findings: ["MITRE lists UAC-0056, Lorec53, TA471 and Storm-0587 as names for one Russian-nexus group active since early 2021, and says it mainly targets organisations in Ukraine and Georgia."] },
    { id: "rf-tag-70", actors: ["winter-vivern"], paraphrased: true, title: "Russia-Aligned TAG-70 Targets European Government and Military Mail Servers in New Espionage Campaign", publisher: "Recorded Future Insikt Group", year: 2024,
      links: [{ label: "Recorded Future research", url: "https://www.recordedfuture.com/research/russia-aligned-tag-70-targets-european-government-and-military-mail" }],
      findings: ["Between October and December 2023 the group exploited cross-site scripting flaws in Roundcube webmail against more than 80 organisations, primarily in Georgia, Poland and Ukraine.",
        "Payload content pointed to the Georgian Ministry of Defence mail server as a target.",
        "Recorded Future reads the focus on Georgian government bodies as interest in Georgia's EU and NATO accession plans."] },
    { id: "bloomberg-2024", actors: [], paraphrased: true, title: "How Russia's Spies Hacked the Entire Nation of Georgia", publisher: "Bloomberg", year: 2024,
      links: [{ label: "Bloomberg (paywalled)", url: "https://www.bloomberg.com/news/articles/2024-10-21/how-russia-s-spies-hacked-the-entire-nation-of-georgia" },
        { label: "Stars and Stripes reprint", url: "https://www.stripes.com/theaters/europe/2024-10-22/how-russia-spies-hacked-georgia-15590579.html" }],
      findings: ["Citing documents and technical reports it reviewed, Bloomberg reported that Russian intelligence penetrated Georgia's Foreign Ministry, Finance Ministry, central bank and major energy and telecom providers between 2017 and 2020.",
        "The access reportedly went beyond espionage and would have allowed interference with energy and communications infrastructure."] },
    { id: "bitdefender-curly-comrades", actors: ["curly-comrades"], paraphrased: true, title: "Curly COMrades: A New Threat Actor Targeting Geopolitical Hotbeds", publisher: "Bitdefender Labs", year: 2025,
      links: [{ label: "Bitdefender report", url: "https://www.bitdefender.com/en-us/blog/businessinsights/curly-comrades-new-threat-actor-targeting-geopolitical-hotbeds" }],
      findings: ["Bitdefender has tracked the group since mid-2024 in focused attacks on judicial and government bodies in Georgia and an energy distributor in Moldova.",
        "The intruders sought long-term access and credentials, using a custom backdoor called MucorAgent alongside proxy and remote-access tools.",
        "Bitdefender did not link the activity to a known group and says only that it aligns with Russian geopolitical goals."] },

    /* General APT29 background reading (from "APT 29/URLs.md"). */
    { id: "apt29-wh-factsheet", actors: ["apt29"], general: true, title: "FACT SHEET: Imposing Costs for Harmful Foreign Activities by the Russian Government", publisher: "The White House", year: 2021, findings: [],
      links: [{ label: "Archived fact sheet", url: "https://web.archive.org/web/20250117194331/https://www.whitehouse.gov/briefing-room/statements-releases/2021/04/15/fact-sheet-imposing-costs-for-harmful-foreign-activities-by-the-russian-government/" }] },
    { id: "apt29-uk-us-expose", actors: ["apt29"], general: true, title: "Russia: UK and US expose global campaign of malign activity by Russian intelligence services", publisher: "UK Government", year: 2021, findings: [],
      links: [{ label: "GOV.UK news", url: "https://www.gov.uk/government/news/russia-uk-and-us-expose-global-campaigns-of-malign-activity-by-russian-intelligence-services" }] },
    { id: "apt29-grizzly-steppe", actors: ["apt29"], general: true, title: "GRIZZLY STEPPE - Russian Malicious Cyber Activity", publisher: "DHS / FBI", year: 2016, findings: [],
      links: [{ label: "Joint Analysis Report (PDF)", url: "https://www.cisa.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf", archived: true }] },
    { id: "apt29-crowdstrike-dnc", actors: ["apt29"], general: true, title: "CrowdStrike’s work with the Democratic National Committee: Setting the record straight", publisher: "CrowdStrike", year: null, findings: [],
      links: [{ label: "CrowdStrike blog", url: "https://www.crowdstrike.com/en-us/blog/bears-midst-intrusion-democratic-national-committee/" }] },
    { id: "apt29-uk-solarwinds", actors: ["apt29"], general: true, title: "Russia: UK exposes Russian involvement in SolarWinds cyber compromise", publisher: "UK Government", year: 2021, findings: [],
      links: [{ label: "GOV.UK news", url: "https://www.gov.uk/government/news/russia-uk-exposes-russian-involvement-in-solarwinds-cyber-compromise" }] },
    { id: "apt29-svr-targets", actors: ["apt29"], general: true, title: "Russian SVR Targets U.S. and Allied Networks", publisher: "NSA / CISA / FBI", year: 2021, findings: [],
      links: [{ label: "Cybersecurity advisory (PDF)", url: "https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF", archived: true },
        { label: "Web Archive copy", url: "https://web.archive.org/web/20260910023245/https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF" }] },
    { id: "apt29-ncsc-solarwinds", actors: ["apt29"], general: true, title: "UK and US call out Russia for SolarWinds compromise", publisher: "UK NCSC", year: 2021, findings: [],
      links: [{ label: "NCSC news", url: "https://www.ncsc.gov.uk/news/uk-and-us-call-out-russia-for-solarwinds-compromise" }] },
    { id: "apt29-sunburst", actors: ["apt29"], general: true, title: "Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor", publisher: "Google Cloud / Mandiant", year: 2020, findings: [],
      links: [{ label: "Threat intelligence blog", url: "https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor" }] },
    { id: "apt29-goldmax", actors: ["apt29"], general: true, title: "GoldMax, GoldFinder, and Sibot: Analyzing NOBELIUM’s layered persistence", publisher: "Microsoft", year: 2021, findings: [],
      links: [{ label: "Microsoft Security blog", url: "https://www.microsoft.com/en-us/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/" }] },
    { id: "apt29-sunspot", actors: ["apt29"], general: true, title: "SUNSPOT: An Implant in the Build Process", publisher: "CrowdStrike", year: null, findings: [],
      links: [{ label: "CrowdStrike blog", url: "https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/" }] },
    { id: "apt29-dark-halo", actors: ["apt29"], general: true, title: "Dark Halo Leverages SolarWinds Compromise to Breach Organizations", publisher: "Volexity", year: 2020, findings: [],
      links: [{ label: "Volexity blog", url: "https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/" }] },
    { id: "apt29-ncsc-ttps", actors: ["apt29"], general: true, title: "Further TTPs associated with SVR cyber actors", publisher: "UK NCSC", year: null, findings: [],
      links: [{ label: "NCSC advisory (PDF)", url: "https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf", archived: true }] },
    { id: "apt29-solarstorm-timeline", actors: ["apt29"], general: true, title: "SolarStorm Supply Chain Attack Timeline", publisher: "Palo Alto Networks Unit 42", year: null, findings: [],
      links: [{ label: "Unit 42 article", url: "https://unit42.paloaltonetworks.com/solarstorm-supply-chain-attack-timeline/" }] },
    { id: "apt29-quorum-profile", actors: ["apt29"], general: true, title: "Midnight Blizzard Threat Actor Profile", publisher: "Quorum Cyber", year: 2023, findings: [],
      links: [{ label: "Threat actor profile (PDF)", url: "https://www.quorumcyber.com/wp-content/uploads/2023/09/Quorum-Cyber-Midnight-Blizzard-APT29-Threat-Actor-Profile.pdf", archived: true }] },
    { id: "apt29-blackpoint-profile", actors: ["apt29"], general: true, title: "Threat Profile: APT29", publisher: "Blackpoint Cyber", year: 2024, findings: [],
      links: [{ label: "Threat profile (PDF)", url: "https://blackpointcyber.com/wp-content/uploads/2024/06/Threat-Profile-APT29_Blackpoint-Adversary-Pursuit-Group-APG_2024.pdf", archived: true }] },
    { id: "apt29-hiveforce", actors: ["apt29"], general: true, title: "Threat Advisory TA2024255", publisher: "HiveForce Labs", year: 2024, findings: [],
      links: [{ label: "Threat advisory (PDF, Web Archive)", url: "https://web.archive.org/web/20250729160054/https://www.hivepro.com/wp-content/uploads/2024/07/TA2024255.pdf", archived: true }] }
  ],

  timeline: [
    { sort: "2008-07-20", when: "20 July 2008", actors: [], report: "nyt-before-the-gunfire",
      title: "First denial-of-service traffic",
      text: "Researchers observe floods aimed at Georgian government websites weeks before the war." },
    { sort: "2008-08-07", when: "7-16 August 2008", actors: [], report: "us-ccu-2008",
      title: "Wartime attack campaign",
      text: "The US Cyber Consequences Unit later concluded civilians and criminal groups carried out the attacks with signs of coordination with the Russian military." },
    { sort: "2011-06", when: "2011-2012", actors: ["georbot"], report: "cert-georgia-georbot",
      title: "Georbot botnet inside state institutions",
      text: "Roughly 300 to 400 computers in ministries, parliament, banks and NGOs are found sending documents to an outside operator." },
    { sort: "2013-02", when: "February 2013", actors: ["apt29"], report: "kaspersky-miniduke",
      title: "MiniDuke victims include Georgia",
      text: "Kaspersky and CrySyS Lab count 59 victims in 23 countries, Georgia among them." },
    { sort: "2015-07", when: "July 2015", actors: [], report: "eset-potao",
      title: "Potao espionage malware reported in Georgia",
      text: "ESET lists Georgia among the post-Soviet countries targeted by the Potao toolkit, active since 2011." },
    { sort: "2018-04", when: "April 2018", actors: ["apt28"], report: "eset-zebrocy",
      title: "Zebrocy victims seen in Georgia",
      text: "ESET names Georgia among 18 countries with victims of APT28's Zebrocy tool, used against embassies and foreign ministries." },
    { sort: "2020-02-20", when: "20 February 2020", actors: ["sandworm"], report: "uk-condemns-gru-2020",
      title: "UK, US and Georgia attribute the 2019 attack to the GRU",
      text: "The UK's NCSC assesses with more than 95% confidence that the GRU was behind the October 2019 defacements and broadcast disruption." },
    { sort: "2020-09-01", when: "1 September 2020", actors: [], report: "lugar-lab-2020",
      title: "Health ministry and Lugar Center breached",
      text: "Georgia's interior ministry blames a foreign intelligence service; stolen records later appear online mixed with forgeries." },
    { sort: "2023-10", when: "October-December 2023", actors: ["winter-vivern"], report: "rf-tag-70",
      title: "Roundcube webmail espionage campaign",
      text: "More than 80 organisations are targeted, mainly in Georgia, Poland and Ukraine, including the Georgian Ministry of Defence mail server." },
    { sort: "2024-06", when: "From mid-2024", actors: ["curly-comrades"], report: "bitdefender-curly-comrades",
      title: "Intrusions into judicial and government bodies",
      text: "Bitdefender tracks a Russia-aligned group seeking long-term access and credentials inside Georgian institutions." },
    { sort: "2024-10-21", when: "21 October 2024", actors: [], report: "bloomberg-2024",
      title: "Bloomberg reports years of Russian access",
      text: "Documents reviewed by Bloomberg describe Russian intelligence inside Georgian ministries, the central bank and energy and telecom providers from 2017 to 2020." },
    { sort: "2008-08", when: "2008", actors: ["apt28"], report: "apt-awareness-review",
      title: "Georgian military targeted during the Russo-Georgian war",
      text: "APT28 is believed to be the group that targeted the Georgian military during the 2008 war." },
    { sort: "2008-08a", when: "2008", actors: ["apt28"], report: "cna-information-confrontation",
      title: "“stopgeorgia” site hosted beside a GRU complex",
      text: "The IP address hosting the “stopgeorgia” website belonged to Steadyhost, a small company essentially collocated with a GRU complex in Moscow." },
    { sort: "2008-08b", when: "2008", actors: [], report: "crs-russian-cyber-units",
      title: "Large-scale cyberattack alongside military action",
      text: "Analysts identified 54 potential targets across government, finance and media. The National Bank of Georgia suspended all electronic operations for 12 days." },
    { sort: "2009-06", when: "June 2009", actors: ["apt29"], report: "dukes",
      title: "PinchDuke campaign “natoinfo_ge”",
      text: "A campaign believed to date from around 7 June 2009 referenced natoinfo.ge, the site of the Georgian Information Centre on NATO." },
    { sort: "2009-07", when: "July 2009", actors: ["apt29"], report: "dukes",
      title: "PinchDuke campaign “mod_ge_2009_07_03”",
      text: "A second campaign identifier a month later apparently targeted the Ministry of Defense of Georgia." },
    { sort: "2010-03", when: "Spring 2010", actors: ["apt29"], report: "dukes",
      title: "PinchDuke campaigns continue",
      text: "Continued PinchDuke campaigns against Turkey and Georgia." },
    { sort: "2011-01", when: "From 2011", actors: ["apt28"], report: "fireeye-apt28-window",
      title: "Georgian-language lures",
      text: "APT28 begins using lures written in Georgian, aimed at the Ministry of Internal Affairs and the Ministry of Defense." },
    { sort: "2013-06", when: "Mid-2013", actors: ["apt28"], report: "fireeye-apt28-window",
      title: "Driver’s-licence lure against the MIA",
      text: "A weaponized Excel file showed a list of Georgian driver’s licence numbers while its backdoor tried to exfiltrate through an MIA mail server." },
    { sort: "2017-01", when: "2017", actors: ["muddywater"], report: "unit42-muddywater",
      title: "Georgia listed among MuddyWater targets",
      text: "Unit 42 lists Georgia among the countries targeted, or suspected to be targeted, throughout 2017." },
    { sort: "2018-01", when: "January 2018", actors: ["sandworm"], report: "doj-gru-indictment",
      title: "Spearphishing of a Georgian media outlet",
      text: "Eight spearphishing emails with a malware-laced attachment were sent to 68 addresses at a Georgian media entity, from an account imitating its name." },
    { sort: "2019-07-31", when: "31 July - 1 August 2019", actors: ["sandworm"], report: "doj-gru-indictment",
      title: "Reconnaissance of the Parliament of Georgia",
      text: "Technical reconnaissance of Parliament’s official domain and an attempt to gain unauthorized access to its network." },
    { sort: "2019-10-28", when: "28 October 2019", actors: ["sandworm"], report: "doj-gru-indictment",
      title: "About 15,000 websites defaced",
      text: "After a Georgian web hosting provider was compromised, government, NGO and private-sector sites were defaced with an image of a former president captioned “I'll be back.”" },
    { sort: "2020-10", when: "October 2020", actors: ["sandworm"], report: "doj-gru-indictment",
      title: "Six GRU officers indicted",
      text: "The U.S. Department of Justice charges six officers of Unit 74455; the indictment lists Georgia among the victims." },
    { sort: "2021-03", when: "March 2021", actors: ["uac-0056"], report: "unit42-outsteel-saintbot",
      title: "Bitcoin- and COVID-themed campaign",
      text: "A spear phishing campaign against targets in Georgia, including a decoy letter from the Ministry of Labour, Health and Social Affairs." },
    { sort: "2021-07", when: "July 2021", actors: ["lorec53"], report: "nsfocus-lorec53",
      title: "Georgian-language phishing documents",
      text: "Macro-laden documents built on current Georgian political topics delivered a document-stealing trojan to government targets." }
  ]
};
