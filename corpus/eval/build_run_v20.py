#!/usr/bin/env python3
"""Construye el JSON intermedio del dry-run v2.0 sobre AA26-204A.

El motor de extraccion fue Claude (sesion de desarrollo del prompt): las decisiones
de QUE extraer y las citas son del modelo aplicando prompt-extraccion-v2.md; este
script solo ensambla el artefacto (las tablas de IOCs se generan desde datos para
evitar typos en 42 valores). NO es el extractor de produccion.
"""
import json

E = []          # entidades
R = []          # relaciones

def ent(eid, etype, value, quote, page, ioc_type=None, aliases=None):
    o = {"id": eid, "type": etype, "value": value, "quote": quote, "page": page}
    if ioc_type: o["ioc_type"] = ioc_type
    if aliases: o["aliases"] = aliases
    E.append(o)

def rel(src, rtype, dst, quote, page):
    R.append({"source": src, "type": rtype, "target": dst, "quote": quote, "page": page})

# ── actor, malware, vulnerabilidad, tecnologias ──────────────────────────────
Q_TRACKING = ("While not exhaustive, the following are threat group names "
              "commonly used for these actors within the cybersecurity community:")
ent("e1", "threat-actor", "LAUNDRY BEAR", Q_TRACKING, 4,
    aliases=["Void Blizzard", "CL-STA-1114", "TA488", "UNK_PitStop"])

Q_ULEJ = ("Using a custom-developed capability [T1587.001] named “Улей” or “Ulej” (Russian for "
          "beehive), LAUNDRY BEAR successfully targeted and exfiltrated sensitive user information "
          "from organizations who use the Zimbra Collaboration Suite (ZCS) product [T1114].")
ent("e2", "malware", "Ulej", Q_ULEJ, 5, aliases=["Улей"])

Q_FLOWERBED = ("It exfiltrates emails and other sensitive user data from a victim’s system "
               "immediately after exploitation and stores the data in an actor-controlled unattributable "
               "virtual private server (VPS) [T1074.002] running LAUNDRY BEAR’s “Flowerbed” "
               "collection framework.")
ent("e3", "malware", "Flowerbed", Q_FLOWERBED, 6)

Q_EVILGINX = ("Once a user entered their Microsoft credentials into this malicious site, LAUNDRY "
              "BEAR’s modified version of the open source adversary emulation toolkit, Evilginx, "
              "intercepted the user’s credentials.")
ent("e4", "malware", "Evilginx", Q_EVILGINX, 5)

Q_EVILGINX2 = ("The dependence on AI for a simple capability, such as Flowerbed, alongside a previous "
               "reliance on open source capabilities, such as Evilginx2 [T1588.002], likely indicates a lack "
               "of advanced technical knowledge within LAUNDRY BEAR, especially in relation to true "
               "software development capabilities.")
ent("e5", "malware", "Evilginx2", Q_EVILGINX2, 8)

Q_CVE = ("The vulnerability, Common Vulnerabilities and Exposures (CVE) CVE-2025-66376, was "
         "patched in November 2025.")
ent("e6", "vulnerability", "CVE-2025-66376", Q_CVE, 2)

Q_ZCS = ("A group of Russian state-supported cyber actors has been targeting and compromising "
         "various Western government and commercial organizations using the Zimbra "
         "Collaboration Suite (ZCS) software since at least July 2025.")
ent("e7", "technology", "Zimbra Collaboration Suite (ZCS)", Q_ZCS, 1)

Q_EXCHANGE = ("The May 2025 advisories highlighted a cluster of activity targeting cloud-based email "
              "environments, including Microsoft Exchange in particular, and abusing legitimate APIs")
ent("e8", "technology", "Microsoft Exchange", Q_EXCHANGE, 4)

Q_MULLVAD = ("LAUNDRY BEAR primarily uses Mullvad VPN [T1583] when interacting with these "
             "servers, further demonstrating the group’s intent to mask their identity and maintain "
             "operations security (OPSEC).")
ent("e9", "technology", "Mullvad VPN", Q_MULLVAD, 7)

Q_PROTON = "LAUNDRY BEAR primarily relied on ProtonMail for distribution of malicious email."
ent("e10", "technology", "ProtonMail", Q_PROTON, 21)

# ── sectores y pais ──────────────────────────────────────────────────────────
Q_SECTORS = ("LAUNDRY BEAR has targeted and compromised users in various organizations, "
             "including those associated with:")
SECTORS = ["the Defense Industrial Base (DIB)", "the federal and local government", "education",
           "energy", "law enforcement", "media", "non-governmental organizations", "technology"]
for i, s in enumerate(SECTORS):
    ent(f"e{11+i}", "sector", s, Q_SECTORS, 6)

Q_US = ("Additionally, extensive Ukrainian targeting, prior to use against U.S. and other NATO allies, "
        "outlines an increasing trend within Russian cyber threat groups to target Ukrainian users "
        "first—both as a priority target and as a testbench for malicious cyber techniques before "
        "broader global deployment.")
ent("e19", "country", "U.S.", Q_US, 5)

# ── attack-patterns (36, todos con T-id literal en la prosa) ─────────────────
Q_COMPILES = ("After identifying a target organization, the group likely compiles email addresses for "
              "individual users to target with the exploit [T1589.002] from datasets offered by "
              "commercial vendors [T1597.002], open source intelligence [T1593], or previously "
              "exfiltrated data [T1597].")
Q_SCAN = ("LAUNDRY BEAR likely identifies organizations with public-facing Zimbra "
          "infrastructure by port scanning [T1595] and fingerprinting datasets easily procured "
          "through various commercial vendors [T1596.005].")
Q_VPS = ("The actors procure VPSs from a variety of providers [T1583.003], including those with "
         "Know Your Customer (KYC) requirements, and often use fabricated identities.")
Q_ZERO = ("Use of a zero-day exploit within this campaign demonstrates the ability for even "
          "emerging threat groups like LAUNDRY BEAR to operationalize novel exploits into a "
          "highly successful capability [T1587].")
Q_ZERODAY = ("Because the activity attributed to "
             "this campaign began in July 2025—months before Synacor released a patch and the "
             "CVE was published—the payload initially exploited a zero-day vulnerability at that time "
             "[T1587.004].")
Q_AI = "This highlights how AI is increasingly being used to develop malicious capabilities [T1588.007]."
Q_STAGE = ("After the server is provisioned, an automated process "
           "deploys the Docker containers necessary for Ulej’s Flowerbed framework [T1608], "
           "which then receives and aggregates the data Ulej exfiltrates.")
Q_VALID = ("The group relied on unsophisticated "
           "means of initial access, including procuring stolen credentials on criminal marketplaces "
           "[T1078], and using social engineering techniques to lure targets into interacting with a "
           "malicious site masquerading as a legitimate one.")
Q_TRUSTED = ("Since at "
             "least November 2025, LAUNDRY BEAR began sending these phishing emails from "
             "victim infrastructure through compromised accounts [T1199], as shown in the email "
             "metadata in Figure 2.")
Q_PHISH = ("To gain initial access, LAUNDRY BEAR sends an email containing a malicious "
           "JavaScript payload to the target [T1566].")
Q_EXPLOIT = ("Through exploitation of CVE-2025-66376, this "
             "JavaScript payload is immediately executed once the user views the malicious email "
             "[T1203], such as the one shown in Figure 1, in the ZCS webmail platform.")
Q_PASSCODE_BULLET = "Newly-created Application Passcode [T1098]."
Q_APPPASS = ("During the "
             "gather_app_password stage, the script makes a SOAP request using the "
             "“CreateAppSpecificPasswordRequest” command under the “zimbraAccount” "
             "namespace to create a new Application Passcode [T1556.006].")
Q_XOR_KEY = ("By changing the key used "
             "for the XOR encryption of the inner payload or adding additional @import directives with "
             "non-functional code [T1027.010], LAUNDRY BEAR can easily generate new payloads "
             "that bypass basic threat detection signatures.")
Q_INNER = ("This payload "
           "includes an XOR encrypted final script encoded in a Base64 inner payload (see Figure "
           "3) [T1027.013].")
Q_SVG = "Graphics (SVG) element [T1027.017], as shown in"
Q_COOKIE = ("Other campaigns attributed to LAUNDRY BEAR also demonstrated the group’s ability to "
            "circumvent multi-factor authentication through session token replay [T1550.004], and "
            "the Zimbra campaign follows a similar trend.")
Q_AITM = ("This method of compromise is commonly known as an "
          "adversary-in-the-middle (AiTM) technique [T1557].")
Q_STAGES12 = ("This malicious payload attempts to collect "
              "and exfiltrate information in 12 asynchronous stages [T1119].")
Q_SOAP_ID = ("If so, the script uses the "
             "“GetIdentitiesRequest” Simple Object Access Protocol (SOAP) command under the "
             "“zimbraAccount” namespace to determine the victim’s email address [T1185] and then "
             "exfiltrates it.")
Q_GZIP = "For email exfiltration, the script sends it as a GZIP compressed archive [T1560]."
Q_GATHER_EMAIL = ("The script used in this campaign tries to discover the victim’s email address during the "
                  "gather_email stage [T1087].")
Q_CATCHER = ("Catcher acts as both a DNS and HTTP server to receive and aggregate exfiltrated "
             "victim information [T1048].")
Q_NGINX = ("This certificate can then be used "
           "by the Nginx container, which serves as an HTTPS reverse proxy for Catcher, enabling "
           "Flowerbed to disguise some of its exfiltration activity through an encrypted "
           "communications channel [T1048.002].")
Q_DNS_HTTPS = ("The script primarily relies on two forms of data "
               "exfiltration: DNS [T1048.003] and HTTPS.")
Q_CREDS = "Password [T1589.001],"
Q_BULK = "to perform data exfiltration in bulk [T1114.002]."

APS = [
    ("T1589.001", "Gather Victim Identity Information: Credentials", Q_CREDS, 5),
    ("T1589.002", "Gather Victim Identity Information: Email Addresses", Q_COMPILES, 7),
    ("T1593", "Search Open Websites/Domains", Q_COMPILES, 7),
    ("T1595", "Active Scanning", Q_SCAN, 7),
    ("T1596.005", "Search Open Technical Databases: Scan Databases", Q_SCAN, 7),
    ("T1597", "Search Closed Sources", Q_COMPILES, 7),
    ("T1597.002", "Search Closed Sources: Purchase Technical Data", Q_COMPILES, 7),
    ("T1583", "Acquire Infrastructure", Q_MULLVAD, 7),
    ("T1583.003", "Acquire Infrastructure: Virtual Private Server", Q_VPS, 7),
    ("T1587", "Develop Capabilities", Q_ZERO, 11),
    ("T1587.001", "Develop Capabilities: Malware", Q_ULEJ, 5),
    ("T1587.004", "Develop Capabilities: Exploits", Q_ZERODAY, 9),
    ("T1588.002", "Obtain Capabilities: Tool", Q_EVILGINX2, 8),
    ("T1588.007", "Obtain Capabilities: Artificial Intelligence", Q_AI, 8),
    ("T1608", "Stage Capabilities", Q_STAGE, 7),
    ("T1078", "Valid Accounts", Q_VALID, 5),
    ("T1199", "Trusted Relationship", Q_TRUSTED, 8),
    ("T1566", "Phishing", Q_PHISH, 8),
    ("T1203", "Exploitation for Client Execution", Q_EXPLOIT, 8),
    ("T1098", "Account Manipulation", Q_PASSCODE_BULLET, 5),
    ("T1556.006", "Modify Authentication Process: Multi-Factor Authentication", Q_APPPASS, 12),
    ("T1027.010", "Obfuscated Files or Information: Command Obfuscation", Q_XOR_KEY, 9),
    ("T1027.013", "Obfuscated Files or Information: Encrypted/Encoded File", Q_INNER, 9),
    ("T1027.017", "Obfuscated Files or Information: SVG Smuggling", Q_SVG, 9),
    ("T1550.004", "Use Alternate Authentication Material: Web Session Cookie", Q_COOKIE, 11),
    ("T1557", "Adversary-in-the-Middle", Q_AITM, 5),
    ("T1074.002", "Data Staged: Remote Data Staging", Q_FLOWERBED, 6),
    ("T1114", "Email Collection", Q_ULEJ, 5),
    ("T1114.002", "Email Collection: Remote Email Collection", Q_BULK, 5),
    ("T1119", "Automated Collection", Q_STAGES12, 9),
    ("T1185", "Browser Session Hijacking", Q_SOAP_ID, 11),
    ("T1560", "Archive Collected Data", Q_GZIP, 17),
    ("T1087", "Account Discovery", Q_GATHER_EMAIL, 11),
    ("T1048", "Exfiltration Over Alternative Protocol", Q_CATCHER, 7),
    ("T1048.002", "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", Q_NGINX, 7),
    ("T1048.003", "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol", Q_DNS_HTTPS, 14),
]
for i, (tid, name, q, pg) in enumerate(APS):
    ent(f"e{20+i}", "attack-pattern", f"{name} [{tid}]", q, pg)

# ── indicadores: Tabla 7 (dominios+IPs), Tabla 8 (SHA-1), emails, SHA-256 ────
TABLE7 = [  # (dominio, ip, fila verbatim)
    ("zmailanalytics[.]com", "216.252.238[.]104", "zmailanalytics[.]com 216.252.238[.]104 8 July 2025 15 October 2025"),
    ("zimbra-metadata[.]com", "216.252.238[.]18", "zimbra-metadata[.]com 216.252.238[.]18 20 August 2025 14 October 2025"),
    ("analyticemailmeter[.]com", "37.120.247[.]228", "analyticemailmeter[.]com 37.120.247[.]228 24 September 2025 18 March 2026"),
    ("emailanalytics.com[.]ua", "185.86.79[.]95", "emailanalytics.com[.]ua 185.86.79[.]95 24 September 2025 18 March 2026"),
    ("mailnalysis[.]com", "104.248.134[.]194", "mailnalysis[.]com 104.248.134[.]194 11 November 2025 17 February 2026"),
    ("zimbrastat[.]com", "64.226.124[.]190", "zimbrastat[.]com 64.226.124[.]190 18 December 2025 18 March 2026"),
    ("zimbrasoft.com[.]ua", "193.238.152[.]66", "zimbrasoft.com[.]ua 193.238.152[.]66 20 January 2026 18 March 2026"),
    ("synacorzimbra[.]nl", "216.252.238[.]64", "synacorzimbra[.]nl 216.252.238[.]64 3 February 2026 30 March 2026"),
    ("istc-cloud[.]com", "194.156.103[.]193", "istc-cloud[.]com 194.156.103[.]193 5 February 2026 30 March 2026"),
]
eid = 56
for dom, ip, row in TABLE7:
    ent(f"e{eid}", "indicator", dom, row, 21, ioc_type="domain"); eid += 1
for dom, ip, row in TABLE7:
    ent(f"e{eid}", "indicator", ip, row, 21, ioc_type="ip"); eid += 1

TABLE8 = [
    ("2e4f314bc9943cab5005d6fde0b271c74d47bc9d", "zmailanalytics[.]com 2e4f314bc9943cab5005d6fde0b271c74d47bc9d 8 Jul 2025 6 Aug 2025"),
    ("50a87d926621dd06389ba50d86e0ff574ed713a8", "*.i.zmailanalytics[.]com 50a87d926621dd06389ba50d86e0ff574ed713a8 6 Aug 2025 13 Oct 2025"),
    ("c5a72420e7bb308d078e62128430897f82194c95", "*.i.zimbra-metadata[.]com c5a72420e7bb308d078e62128430897f82194c95 20 Aug 2025 14 Oct 2025"),
    ("8959c4d29e29f02ea94ea8bb21c8df2594c5549d", "*.i.analyticemailmeter[.]com 8959c4d29e29f02ea94ea8bb21c8df2594c5549d 24 Sep 2025 8 Nov 2025"),
    ("62eb76432597694edb01c1fe57aab0cfe03a7178", "*.i.emailanalytics.com[.]ua 62eb76432597694edb01c1fe57aab0cfe03a7178 25 Sep 2025 27 Sep 2025"),
    ("cddf5c3be1e07f28140aed165b929bf2d614922a", "*.i.mailnalysis[.]com cddf5c3be1e07f28140aed165b929bf2d614922a 12 Nov 2025 17 Dec 2025"),
    ("18b3ad442ce73cc8656d51d75bbd7c855f2cb7e8", "*.i.zimbrastat[.]com 18b3ad442ce73cc8656d51d75bbd7c855f2cb7e8 18 Dec 2025 28 Dec 2025"),
    ("1b25041ececf2457eef0270fc1d785cec8ec9ded", "*.i.zimbrasoft.com[.]ua 1b25041ececf2457eef0270fc1d785cec8ec9ded 21 Jan 2026 10 Feb 2026"),
    ("e4fe6466a4f9a4249fe330651e914e45bbdca44a", "*.i.synacorzimbra[.]nl e4fe6466a4f9a4249fe330651e914e45bbdca44a 5 Feb 2026 22 Mar 2026"),
    ("b6b77c9a455225d525834a403ca9ef5481ed0447", "*.i.istc-cloud[.]com b6b77c9a455225d525834a403ca9ef5481ed0447 12 Feb 2026 30 Mar 2026"),
]
for h, row in TABLE8:
    ent(f"e{eid}", "indicator", h, row, 21, ioc_type="hash_sha1"); eid += 1

EMAILS_PROCURE = ["ivanka.zurabishvili@proton[.]me", "zmul1@buildandconsulting[.]com",
                  "garrysmithme@pinmx[.]net", "hostingclient@pinmx[.]net"]
for m in EMAILS_PROCURE:
    ent(f"e{eid}", "indicator", m, f"{m},", 21, ioc_type="email"); eid += 1
# la ultima bullet termina en "and" no coma
E[-1]["quote"] = "hostingclient@pinmx[.]net."

EMAILS_PHISH = ["c.laurent.ejfa@proton[.]me", "j.moreau.epsc@proton[.]me", "liberty.insights@proton[.]me"]
for m in EMAILS_PHISH:
    ent(f"e{eid}", "indicator", m, f"{m},", 21, ioc_type="email"); eid += 1
E[-1]["quote"] = "liberty.insights@proton[.]me,"
E[-1]["page"] = 22

Q_ISOFTS = ("certain email addresses (presumably compromised) at the isofts.kiev[.]ua domain "
            "(i.e., ending with @isofts.kiev[.]ua), and")
ent(f"e{eid}", "indicator", "isofts.kiev[.]ua", Q_ISOFTS, 22, ioc_type="domain"); eid += 1
Q_NAVS = ("certain email addresses (presumably compromised) at the navs.edu[.]ua domain "
          "(i.e., ending with @navs.edu[.]ua).")
ent(f"e{eid}", "indicator", "navs.edu[.]ua", Q_NAVS, 22, ioc_type="domain"); eid += 1

SHA256S = ["98df604ecc57f884a2e6ce3266a0013ad64455cac48442c2312cfa4765007aaf",
           "60db9abae75cd8ccc49dd7ea5feb41677566dcd442f12ebc5745ffd2810fb874",
           "b1f5beb1175fc5c7d1806a2f0d900eb124c54f0286c5c52b66eea7a6633adb1d",
           "1517b3caa495f6c4e832df9c75fc94667e3c233773f7fa4e056d5e30e5ead760"]
for h in SHA256S:
    ent(f"e{eid}", "indicator", h, f"{h},", 22, ioc_type="hash_sha256"); eid += 1

Q_PIXEL = ("The HTTP server typically responds with OK, except in cases where the path is "
           "“pixel.gif” when the response contains a 1x1 gif image with a SHA-256 hash of "
           "ef1955ae757c8b966c83248350331bd3a30f658ced11f387f8ebf05ab3368629.")
ent(f"e{eid}", "indicator", "ef1955ae757c8b966c83248350331bd3a30f658ced11f387f8ebf05ab3368629",
    Q_PIXEL, 18, ioc_type="hash_sha256")
PIXEL_ID = f"e{eid}"; eid += 1

# ── relaciones ───────────────────────────────────────────────────────────────
Q_USES_ULEJ = ("LAUNDRY BEAR uses the Ulej capability to exploit the CVE-2025-66376 vulnerability in "
               "organizations using ZCS.")
rel("e1", "uses", "e2", Q_USES_ULEJ, 6)
rel("e1", "exploits", "e6", Q_USES_ULEJ, 6)
Q_ULEJ_CVE = ("This capability is used to exploit CVE-2025-66376 [Common "
              "Weakness Enumeration (CWE) CWE-79: Improper Neutralization of Input During Web "
              "Page Generation ('Cross-site Scripting')], but likely could be adapted to exploit other "
              "vulnerabilities.")
rel("e2", "exploits", "e6", Q_ULEJ_CVE, 6)
rel("e1", "uses", "e3", Q_FLOWERBED, 6)
rel("e1", "uses", "e4", Q_EVILGINX, 5)
rel("e1", "uses", "e5", Q_EVILGINX2, 8)
rel("e1", "uses", "e9", Q_MULLVAD, 7)
rel("e1", "uses", "e10", Q_PROTON, 21)
rel("e1", "targets", "e7", Q_ZCS, 1)
for i in range(8):
    rel("e1", "targets", f"e{11+i}", Q_SECTORS, 6)

Q_ATTRIB = ("The following indicators have been attributed to use by LAUNDRY BEAR for their "
            "campaign targeting ZCS’s webmail service as of the publication of this advisory.")
for n in range(56, 84):          # tabla 7 + tabla 8
    rel(f"e{n}", "indicates", "e1", Q_ATTRIB, 20)
Q_PROCURE = ("LAUNDRY BEAR has used the following email addresses to procure resources used for "
             "this campaign:")
for n in range(84, 88):
    rel(f"e{n}", "indicates", "e1", Q_PROCURE, 21)
Q_DISTRIB = "The following email addresses have distributed payloads attributed to this campaign:"
for n in range(88, 93):
    rel(f"e{n}", "indicates", "e1", Q_DISTRIB, 21)
Q_SAMPLES = ("Additionally, the following are SHA-256 hashes of email samples containing the "
             "malicious payload attributed to this campaign:")
for n in range(93, 97):
    rel(f"e{n}", "indicates", "e1", Q_SAMPLES, 22)

OUT = {
    "entities": E,
    "relationships": R,
    "campaign_summary": (
        "Russian state-supported actor LAUNDRY BEAR has been exploiting CVE-2025-66376, a "
        "cross-site scripting zero-day in Zimbra Collaboration Suite webmail, since July 2025 using a "
        "custom capability named Ulej that exfiltrates 90 days of email, credentials, 2FA tokens and "
        "the Global Address List simply when a victim views a malicious email. Stolen data flows over "
        "DNS and HTTPS to the actor's Flowerbed collection framework on short-lived VPS "
        "infrastructure. Targets span Western government, defense, energy, education, media and "
        "technology organizations, for espionage purposes benefiting the Russian Federation."),
}
with open("runs/aa26-204a.v2.0.json", "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
    f.write("\n")
print(f"entidades: {len(E)}  relaciones: {len(R)}")
from collections import Counter
print(Counter(e["type"] for e in E))
