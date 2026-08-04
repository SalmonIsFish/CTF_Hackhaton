# Web

## Overview

Web CTF challenges focus on how websites and web applications work. They often ask you to inspect pages, understand requests and responses, notice hidden information, or reason about how a login, form, cookie, or API behaves. For beginners, the most important skill is learning to slow down and observe what the browser and server are doing.

In a CTF, web challenges are usually safe practice environments made for learning. They may contain simplified versions of real web security ideas, such as broken access checks, confusing input handling, exposed files, or information hidden in client-side code. The goal is not to attack real websites, but to build careful thinking about how web systems are built and where mistakes can appear.

Good web CTF habits include reading the page source, checking browser developer tools, comparing different requests, and keeping clear notes. Many challenges can be solved by understanding basic web concepts rather than using advanced tools. A calm, methodical approach is often more useful than guessing.

## Key Concepts

### [[HTTP]]

HTTP stands for Hypertext Transfer Protocol. It is the basic language that browsers and web servers use to communicate. When you visit a website, your browser sends an HTTP request asking for something, such as a page, image, script, or API response. The server sends back an HTTP response with a status code, headers, and usually some content. In CTFs, understanding [[HTTP]] helps you see what the browser is asking for and what the server is returning. Important ideas include request methods, status codes, headers, and response bodies. HTTP is plain text by design, which makes it easier to study in a lab. Many web CTF tasks involve noticing small differences between requests or finding useful information in a response.

### [[HTTPS]]

HTTPS is the secure version of [[HTTP]]. It uses encryption to protect traffic between your browser and the website. This helps stop other people on the network from casually reading or changing the data in transit. In normal web browsing, HTTPS is very important for privacy, login pages, payment pages, and any site that handles personal information. In CTFs, HTTPS usually works the same way as on the real web, but the challenge may still show you request and response details through local tools or browser developer tools. The main beginner idea is that HTTPS protects transport, not the whole application. A site can use HTTPS and still have logic mistakes, exposed files, weak access control, or other security issues inside the application itself.

### [[URL]]

A URL, or Uniform Resource Locator, is the address of something on the web. A typical URL includes a scheme such as `http` or `https`, a domain name, an optional path, and sometimes query parameters. The path often points to a page or resource, while query parameters pass small pieces of information to the server. In CTFs, URLs are useful because they show what resource the browser is requesting and what values may be sent with the request. Beginners should learn to identify the different parts of a URL and compare how pages change when values change. A URL can also reveal structure, such as directories, file names, or API routes. Reading URLs carefully is a simple but powerful habit.

### [[Cookies]]

Cookies are small pieces of data that a website asks your browser to store. The browser sends relevant cookies back to the same site in future requests. Websites commonly use cookies to remember preferences, track sessions, or keep a user logged in. In CTFs, [[Cookies]] are important because they may contain clues, identifiers, or settings that affect how the site responds. A cookie is not automatically secret just because it is stored by the browser. Some cookies are readable by client-side code, while others have protections that limit access. Beginners should understand that cookies are part of the conversation between browser and server. Looking at cookie names, values, and settings can help explain why a page behaves differently for different users.

### [[Sessions]]

Sessions are a way for a website to remember a user across multiple requests. Since [[HTTP]] is mostly stateless, the server needs some method to connect separate page visits into one ongoing interaction. A common pattern is that the browser stores a session cookie, and the server uses that cookie to look up session data. In CTFs, [[Sessions]] often appear in login systems, shopping carts, dashboards, and user roles. The important beginner idea is that the cookie may only be an identifier, while the real session data may live on the server. If session handling is designed poorly, a challenge might show confusing identity or permission behavior. Understanding sessions helps you reason about logged-in state without needing to know every server detail.

### [[HTML]]

HTML stands for Hypertext Markup Language. It describes the structure and content of a web page. Headings, paragraphs, links, images, forms, buttons, tables, and many other page elements are written in HTML. Your browser reads HTML and turns it into the page you see. In CTFs, [[HTML]] is one of the first places beginners should inspect because it may contain comments, hidden fields, links to scripts, or clues about how the page is organized. HTML is not the same as secret server code. Anything sent to the browser can be viewed by the user. This matters because challenge authors sometimes place hints in the visible structure or source code. Learning basic HTML makes web pages feel much less mysterious.

### [[CSS]]

CSS stands for Cascading Style Sheets. It controls how HTML elements look, including colors, layout, fonts, spacing, visibility, and responsive behavior. CSS does not usually control server-side security decisions, but it can affect what a user sees on the page. In CTFs, [[CSS]] may be useful when something is hidden visually but still present in the page. For example, an element might be styled so it does not appear normally, even though it exists in the HTML. CSS files can also contain comments, asset paths, or naming clues. Beginners should treat CSS as part of the front-end evidence. It helps explain presentation and layout, and sometimes it points toward other files worth inspecting in a safe challenge environment.

### [[JavaScript]]

JavaScript is a programming language that runs in the browser and sometimes on servers. On web pages, it is used for interactivity, form behavior, dynamic content, and communication with APIs. In CTFs, [[JavaScript]] is often important because it may reveal how a page sends requests, validates input, or loads hidden data. Since browser JavaScript is sent to the user, it should not be treated as a safe place for real secrets. Beginners can learn a lot by reading script files and using browser developer tools to see network activity. JavaScript can make pages feel complicated, but the basic question is simple: what is the page doing after it loads, and what extra resources is it requesting?

### [[HTTP Headers]]

HTTP headers are small pieces of metadata sent with HTTP requests and responses. Request headers can tell the server about the browser, accepted content types, cookies, origin, or authentication details. Response headers can tell the browser about content type, caching, redirects, cookies, and security-related settings. In CTFs, [[HTTP Headers]] can contain useful clues or explain why a page behaves a certain way. For example, a redirect header may point to another location, or a response header may reveal information about the server or application. Headers are not usually visible on the page itself, so browser developer tools or HTTP inspection tools are useful for studying them. Beginners should learn to read headers as part of the full web conversation.

### [[Forms]]

Forms are parts of web pages that collect user input. Login boxes, search bars, contact pages, upload pages, and profile settings are common examples. A form usually has input fields and a submit action that sends data to the server. In CTFs, [[Forms]] are important because they show what information the application expects and where that information is sent. Hidden form fields may also be present in the HTML, even if they are not visible on the page. Beginners should understand that client-side form restrictions, such as dropdowns or length limits, are mainly for convenience and usability. The server still needs to decide what is valid. Studying forms helps you understand the application's workflow and data flow.

### [[GET vs POST]]

GET and POST are two common HTTP request methods. GET is usually used to request information, and its parameters often appear in the URL. POST is usually used to send data in the request body, such as login details, form submissions, or settings changes. In CTFs, knowing [[GET vs POST]] helps you understand where input is being placed and how the server receives it. GET requests are easy to notice because values may be visible in the address bar. POST requests are less visible on the page, but they can be inspected with browser developer tools. Neither method is automatically secure by itself. The meaning comes from how the application handles the request, checks permissions, and protects sensitive data.

### [[Authentication]]

Authentication is the process of proving who you are. A login form is the most familiar example: you provide a username and password, and the application decides whether they match a real account. Other authentication methods can include one-time codes, passkeys, or tokens. In CTFs, [[Authentication]] appears when a challenge includes accounts, login pages, or protected areas. Beginners should separate authentication from authorization. Authentication answers, "Who is this user?" It does not automatically mean the user is allowed to do everything. In a learning challenge, authentication clues may appear in forms, cookies, session behavior, or error messages. The safe goal is to understand the design and notice inconsistencies, not to target real systems.

### [[Authorization]]

Authorization is the process of deciding what an authenticated user is allowed to access or do. For example, a normal user may view their own profile, while an administrator may manage many accounts. Authorization depends on roles, permissions, ownership, and server-side checks. In CTFs, [[Authorization]] matters because some challenges are built around access control mistakes. A page may exist, but not every user should be allowed to see it. A button may be hidden, but the server still needs to enforce the rule. Beginners should remember that hiding links in the interface is not the same as proper authorization. The key question is whether the application consistently checks permissions for each sensitive action or resource.

### [[SQL Injection]]

SQL Injection is a security concept involving databases. Many websites use SQL databases to store users, posts, products, scores, or other information. SQL Injection can happen when an application mixes user input into a database query without safely separating data from commands. In real systems, this can be dangerous because it may affect confidentiality, integrity, or availability of data. In beginner CTFs, [[SQL Injection]] is usually presented as a controlled lesson about input handling and query design. The important concept is that applications should use safe database APIs, prepared statements, and careful validation. This note does not include attack strings or walkthrough steps. Focus on the defensive lesson: user input should be treated as data, never trusted as part of a command.

### [[XSS]]

Cross Site Scripting, often called XSS, is a security concept involving untrusted content shown in a web page. It can happen when an application places user-controlled text into HTML or JavaScript context without proper handling. In real systems, XSS can affect users because code may run in their browsers under the trusted site. In CTFs, [[XSS]] is often used to teach why output encoding, content security policies, and safe templating matter. Beginners should understand the idea at a high level: websites must be careful when displaying anything that came from a user, a URL, a database, or another external source. This note avoids payloads and exploitation steps, keeping the focus on recognition and prevention.

### [[Directory Traversal]]

Directory Traversal is a security concept involving file paths. Web applications sometimes read files based on names, paths, or parameters. A problem can occur when the application does not properly limit which files are allowed. In real systems, this may expose files that were not meant to be public. In CTFs, [[Directory Traversal]] is commonly introduced as a lesson about safe file access and strict path handling. Beginners should understand that servers have file systems with directories, and web apps should only serve approved files from approved locations. The defensive lesson is to avoid trusting raw user input as a file path, use allowlists where possible, and keep sensitive files outside public web directories. This note does not provide traversal strings or step-by-step exploitation.

### [[Local File Inclusion]]

Local File Inclusion, or LFI, is a concept where a web application includes or reads a file from its own server based on input. This can be risky if the application lets users influence the file choice too freely. In real systems, LFI may expose sensitive local files or cause unexpected application behavior. In CTFs, [[Local File Inclusion]] is usually a controlled way to teach why file inclusion features need strict rules. Beginners should focus on the design issue: a server should not include arbitrary local files just because a request asks for them. Safe applications use fixed templates, allowlisted names, careful path resolution, and permission boundaries. This note keeps LFI at the concept level and avoids exploit procedures.

### [[Remote File Inclusion]]

Remote File Inclusion, or RFI, is a concept where an application includes content from an external location based on input. This is risky because remote content may be controlled by someone outside the application. In real systems, unsafe remote inclusion can lead to serious security problems, especially if included content is treated as trusted code or trusted configuration. In CTFs, [[Remote File Inclusion]] is often used to teach the danger of fetching and using external resources without strict validation. Beginners should remember that not all links, URLs, or remote files are safe just because they are reachable. The defensive lesson is to avoid dynamic remote inclusion unless it is truly necessary, tightly restricted, and safely handled. This note does not include exploitation steps.

## Common Public Tools

### [[Burp Suite]]

- Purpose: A web security testing platform for inspecting and modifying HTTP traffic in authorized environments.
- Common CTF use: Viewing requests and responses, studying cookies, checking headers, and understanding how forms or APIs communicate.
- Official website: [https://portswigger.net/burp](https://portswigger.net/burp)

### [[CyberChef]]

- Purpose: A browser-based tool for encoding, decoding, formatting, hashing, and transforming data.
- Common CTF use: Decoding text, converting formats, inspecting strange strings, and chaining simple data transformations.
- Official website: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### [[Gobuster]]

- Purpose: A command-line tool often used to discover web paths, DNS names, and other wordlist-based matches in authorized labs.
- Common CTF use: Finding challenge directories or files that are intentionally hidden from normal navigation.
- Official website: [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster)

### [[dirb]]

- Purpose: A web content scanner that checks for common directories and files using wordlists in authorized environments.
- Common CTF use: Discovering hidden web paths that the challenge creator expects players to find.
- Official website: [https://dirb.sourceforge.net/](https://dirb.sourceforge.net/)

### [[sqlmap]]

- Purpose: An automated SQL Injection testing tool for authorized security testing and lab practice.
- Common CTF use: Understanding database-related challenge behavior in controlled environments where automation is allowed.
- Official website: [https://sqlmap.org/](https://sqlmap.org/)

### [[curl]]

- Purpose: A command-line tool for making web requests and viewing responses from URLs.
- Common CTF use: Checking pages, headers, redirects, cookies, and API responses without relying only on a browser.
- Official website: [https://curl.se/](https://curl.se/)

### [[Postman]]

- Purpose: A platform for building, testing, and documenting APIs.
- Common CTF use: Sending structured API requests, organizing endpoints, and comparing JSON responses in web challenges.
- Official website: [https://www.postman.com/](https://www.postman.com/)

### [[Browser Developer Tools]]

- Purpose: Built-in browser tools for inspecting HTML, CSS, JavaScript, storage, network traffic, and console messages.
- Common CTF use: Reading page structure, viewing network requests, checking cookies, inspecting scripts, and understanding front-end behavior.
- Official website: [Chrome DevTools](https://developer.chrome.com/docs/devtools/) and [Firefox Developer Tools](https://firefox-source-docs.mozilla.org/devtools-user/)

## Where Flags Usually Hide

Flags in beginner web CTFs are often placed where careful inspection matters more than advanced technique. The page source is a common starting point because it shows the HTML sent to the browser. HTML comments may contain hints or unused notes. Linked [[JavaScript]] files can reveal routes, API names, or client-side logic. CSS files may also point to assets or hidden elements.

Hidden directories and files may exist as part of the challenge design. Response headers can include unusual values or hints. [[Cookies]] may contain readable settings, identifiers, or clues. Files such as `robots.txt` and `sitemap.xml` can reveal paths that are not linked from the main page. Hidden forms or hidden input fields may show values that are submitted with a request.

API responses are also worth reading carefully. A page may display only part of the data returned by an API, while the full response contains extra fields. Browser developer tools can help you see these responses in a safe lab setting. The key beginner habit is to inspect what the server sends, compare pages and responses, and record anything that looks intentional or unusual. Avoid trying these ideas on real websites without clear permission.

## Beginner Study Links

### picoCTF

[picoCTF](https://picoctf.org/) is a beginner-friendly CTF platform created for learning cybersecurity through small challenges. Its web problems often introduce core ideas like page source inspection, cookies, simple authentication logic, and basic request analysis. It is a good place to start because the challenges are designed for students and include a wide range of difficulty levels.

### OverTheWire

[OverTheWire](https://overthewire.org/wargames/) offers wargames that teach security concepts through hands-on practice. While it is especially well known for Linux and command-line learning, it also helps build the careful problem-solving habits needed for web CTFs. Beginners can use it to become more comfortable reading files, using terminals, and thinking step by step.

### PortSwigger Web Security Academy

[PortSwigger Web Security Academy](https://portswigger.net/web-security) is a free learning platform focused on web security. It provides clear explanations and lab environments for many web vulnerability concepts. Beginners should use it carefully and educationally, focusing on understanding how web applications fail and how developers can prevent those failures.

### TryHackMe

[TryHackMe](https://tryhackme.com/) is a guided cybersecurity learning platform with rooms, paths, and exercises for many skill levels. Its beginner web content can help learners understand HTTP, authentication, common web mistakes, and tool usage in legal practice environments. It is useful for people who prefer structured lessons with explanations along the way.

### Hack The Box Academy

[Hack The Box Academy](https://academy.hackthebox.com/) provides structured modules about cybersecurity topics, including web fundamentals and web application security. It is more course-like than a traditional CTF scoreboard, which can be helpful for beginners who want explanations before challenges. Its learning paths can support steady progress from basic web concepts to more advanced defensive understanding.

## Related Notes

- [[HTTP]]
- [[HTTPS]]
- [[URL]]
- [[Cookies]]
- [[Sessions]]
- [[HTML]]
- [[CSS]]
- [[JavaScript]]
- [[HTTP Headers]]
- [[Forms]]
- [[GET vs POST]]
- [[Authentication]]
- [[Authorization]]
- [[SQL Injection]]
- [[XSS]]
- [[Directory Traversal]]
- [[Local File Inclusion]]
- [[Remote File Inclusion]]
- [[Burp Suite]]
- [[CyberChef]]
- [[Gobuster]]
- [[dirb]]
- [[sqlmap]]
- [[curl]]
- [[Postman]]
- [[Browser Developer Tools]]

