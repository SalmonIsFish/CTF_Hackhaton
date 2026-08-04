# Red Team Basics

## What is Red Teaming?

[[Red Teaming]] is a controlled way to test how well an organization can prevent, detect, and respond to security problems. A [[Red Team]] acts like a realistic attacker, but only within approved rules, legal boundaries, and agreed goals. The purpose is not to cause harm. The purpose is to help people find weak spots before real attackers do.

For non-cybersecurity beginners, think of [[Red Teaming]] like a fire drill for computer systems, buildings, people, and processes. The team checks what could go wrong, how defenders notice it, and how quickly the organization can respond. Good [[Red Teaming]] is planned, documented, ethical, and focused on learning.

## Key Terms

- [[Recon]]: Recon, short for reconnaissance, means gathering basic information before making decisions. In cybersecurity, it can include learning about a company, its public websites, technologies, staff roles, domains, or exposed services. In a legal [[Red Teaming]] exercise, recon happens only within the approved scope. For beginners, recon is like looking at a map before taking a trip: it helps people understand the environment. In [[CTF]] challenges, recon often means reading the challenge carefully, checking file details, identifying obvious clues, and forming a plan. Recon is about observation, context, and careful note-taking, not jumping straight into tools.

- [[OSINT]]: OSINT means open-source intelligence. It refers to information gathered from public sources, such as websites, search engines, public documents, social media, domain records, code repositories, news, and job postings. [[OSINT]] is not the same as hacking; it focuses on information that is already publicly available. In [[Red Teaming]], OSINT can help identify what an organization unintentionally reveals. For beginners, OSINT is similar to researching a topic online, but with a structured security purpose. Ethical OSINT respects laws, privacy, and scope. In [[CTF]] challenges, OSINT puzzles may require searching public clues to find a flag.

- [[Enumeration]]: Enumeration means listing and identifying details about a target environment after initial discovery. It may involve cataloging systems, services, users, files, directories, software versions, or configuration details. In beginner terms, [[enumeration]] is making an inventory of what exists so you can understand the situation clearly. In authorized [[Red Teaming]], enumeration must stay within the agreed scope and avoid unnecessary disruption. In [[CTF]] challenges, enumeration is often one of the most important habits because hidden clues are easy to miss. Good enumeration is patient and organized. It helps turn vague information into a clear checklist of facts.

- [[Vulnerability]]: A vulnerability is a weakness that could allow something unintended to happen. It might be a software bug, a weak password policy, a missing update, an exposed file, a risky setting, or a confusing process. Not every vulnerability is equally serious; impact depends on context. For beginners, a [[vulnerability]] is like an unlocked side door or a broken window latch. In [[Red Teaming]], vulnerabilities are documented so teams can understand and fix them. In [[CTF]] challenges, the vulnerability is usually the intended puzzle weakness. Learning to recognize vulnerabilities builds defensive awareness, not just technical curiosity.

- [[Exploit]]: An exploit is something that takes advantage of a [[vulnerability]] to produce a specific result. In real organizations, exploit use must be legal, authorized, and carefully controlled because it can cause damage. For beginners, imagine a vulnerability as a broken lock and an exploit as a method that proves the lock can be opened. In [[Red Teaming]], exploits may be discussed or demonstrated only under strict rules of engagement. In [[CTF]] challenges, exploits are part of controlled learning environments. The important beginner lesson is understanding risk: a weakness matters more when someone can reliably use it.

- [[Payload]]: A payload is the part of an action or test that carries out the intended effect after a weakness is reached. The word can sound dramatic, but it simply means "the thing delivered." In security discussions, payloads can be harmless proof messages, test files, commands, or more complex code, depending on the environment. In ethical [[Red Teaming]], payloads are carefully chosen to avoid unnecessary harm and to prove a point safely. For beginners, a payload is like the note placed inside a package. In [[CTF]] challenges, payloads are often simplified and used inside isolated practice systems.

- [[Privilege Escalation]]: Privilege escalation means moving from a lower level of access to a higher level of access. For example, a normal user account has fewer permissions than an administrator account. In beginner terms, [[privilege escalation]] is like going from a guest badge to a staff badge, but in computing systems. In authorized [[Red Teaming]], this concept helps show what could happen if one account or system is compromised. It also helps defenders understand where stronger controls are needed. In [[CTF]] practice, privilege escalation is often a learning step inside a sandboxed machine or lab.

- [[Lateral Movement]]: Lateral movement means moving from one system, account, or area to another within an environment. It describes how a problem can spread after an initial foothold. For beginners, imagine entering one room in a building and then finding doors to other rooms. In [[Red Teaming]], lateral movement is studied to understand whether internal boundaries, monitoring, and access controls are strong enough. It should only occur in approved test environments and within scope. In [[CTF]] challenges, lateral movement may appear as progressing from one user, service, or machine to another while solving a staged scenario.

- [[Persistence]]: Persistence means maintaining access over time. In real attacks, persistence is dangerous because it can let an intruder return after a reboot, password change, or temporary interruption. In ethical [[Red Teaming]], persistence is handled with extreme care, explicit permission, and cleanup planning. For beginners, think of persistence as leaving a spare key somewhere, which is why defenders care deeply about finding and removing it. In [[CTF]] challenges, persistence is usually discussed conceptually rather than needed for beginner tasks. The defensive lesson is that security teams must check for changes that allow repeated unauthorized access.

- [[Exfiltration]]: Exfiltration means taking data out of an environment. In real incidents, this could involve sensitive files, credentials, personal information, or business records. In beginner language, [[exfiltration]] is the digital version of removing documents from a locked office. Ethical [[Red Teaming]] may simulate exfiltration using harmless sample data to test whether monitoring and response processes work. It should never involve stealing real private data. In [[CTF]] challenges, exfiltration may simply mean finding and submitting a flag. The key lesson is that protecting data includes detecting when it leaves places where it belongs.

- [[Blue Team]]: The Blue Team is responsible for defense. They monitor systems, investigate alerts, patch weaknesses, improve configurations, write detection rules, respond to incidents, and help keep people and data safe. For beginners, the [[Blue Team]] is like the safety crew, security desk, and maintenance team combined. They want to understand what is normal, notice what is suspicious, and respond calmly when something goes wrong. In organizations, Blue Teams work with IT, leadership, legal teams, and users. In [[CTF]] or training environments, Blue Team exercises teach investigation, log review, detection, and incident response skills.

- [[Red Team]]: The Red Team is the group that plays the role of a realistic adversary during an authorized security exercise. Their job is to test defenses, identify weaknesses, and show how different issues could connect into larger risk. A good [[Red Team]] does not simply "break things"; it communicates clearly, follows scope, avoids unnecessary harm, and produces useful lessons. For beginners, the Red Team is like a professional inspection team that tests whether locks, alarms, policies, and responses work together. In [[CTF]] learning, red-team-style thinking means creative problem solving inside safe, legal practice environments.

- [[Purple Team]]: A Purple Team is a collaborative approach that brings [[Red Team]] and [[Blue Team]] perspectives together. Instead of treating offense and defense as separate groups, [[Purple Team]] work focuses on shared learning. The Red Team explains what it tested, while the Blue Team improves visibility, detection, and response. For beginners, purple teaming is like a practice session where the testers and defenders compare notes after each round. It helps organizations improve faster because lessons become immediate and practical. In training, Purple Team exercises are useful for understanding how actions, logs, alerts, and defenses connect.

- [[CTF]]: CTF means Capture the Flag. It is a cybersecurity learning game where participants solve puzzles and submit hidden text called flags. [[CTF]] challenges can cover [[forensics]], [[web security]], [[cryptography]], [[reverse engineering]], [[OSINT]], [[misc]], and beginner command-line skills. CTFs are designed to be legal, contained, and educational. For non-cybersecurity beginners, a CTF is like a puzzle hunt with technical themes. The goal is not to attack real systems, but to practice curiosity, careful reading, research, and problem solving. CTFs are one of the safest ways to explore security concepts hands-on.

## Common Red Team Tools

- [[Nmap]]: A network discovery and service identification tool. Its purpose is to help understand what systems and services are present in an authorized environment.
- [[Burp Suite]]: A web application security testing platform. Its purpose is to help inspect and understand web traffic between a browser and an application during approved testing.
- [[Wireshark]]: A packet analysis tool. Its purpose is to view and understand network traffic, protocols, and packet details for troubleshooting, learning, and investigation.
- [[CyberChef]]: A browser-based data transformation tool. Its purpose is to encode, decode, convert, format, and inspect data in a visual workspace.
- [[Metasploit]]: A security testing framework. Its purpose is to help professionals validate and document known security issues in controlled, authorized environments.

## Learning Resources

- [picoCTF](https://picoctf.org/) - Beginner-friendly [[CTF]] practice with approachable challenges.
- [TryHackMe](https://tryhackme.com/) - Guided cybersecurity learning rooms for beginners and intermediate learners.
- [OverTheWire](https://overthewire.org/wargames/) - Wargames that build command-line, Linux, and security fundamentals.
- [Hack The Box Academy](https://academy.hackthebox.com/) - Structured cybersecurity modules and practical labs.

## Related Notes

- [[CTF Basics]]
- [[Forensics Misc]]
- [[Web Security]]
- [[Linux Commands]]
- [[Networking Basics]]
- [[OSINT]]
- [[Blue Team Basics]]
- [[Cybersecurity Ethics]]
- [[Wireshark]]
- [[Nmap]]

