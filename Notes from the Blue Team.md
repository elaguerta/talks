Elaine Laguerta, Senior Security Engineer, New Relic
August 29, 2024
Portland Python User Group Meetup

## I. Things you should know

#### 1.  If a secret has been committed, consider it pwned.
- Orphaned commits 
![Pasted image 20240827214234.jpg]
Julia Evans, https://wizardzines.com/comics/orphan-commits/
- [It only takes the bad guys 1 minute](https://www.comparitech.com/blog/information-security/github-honeypot/)

#### 2. Hashing != encryption. Encryption != privacy. 

- Webhook signing with a shared secret
![Pasted image 20240829042754.png]
(https://hookdeck.com/webhooks/guides/how-to-implement-sha256-webhook-signature-verification)

- Document signing with asymmetric keys
![Pasted image 20240829045530.png]
(https://sergioprado.blog/asymmetric-key-encryption-and-digital-signatures-in-practice/)

- Symmetric key encryption
![Pasted image 20240829040453.png]
(By MarcT0K (icons by JGraph) - Own work, CC BY-SA 4.0, https://commons.wikimedia.org/w/index.php?curid=128651167)

| cryptography | direction                                                     | speed   | secrets?                                                                             | Decryptable?                                                                                         | Functions                         | applications                                                                                                                       |
| ------------ | ------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Hash         | one way                                                       | fastest | Sometimes: -  password (not shared) - webhook secret (shared) - commits (no secrets) | No                                                                                                   | Authentication, Message integrity | - passwords -commits - container images -distributed artifacts                                                                     |
| Asymmetric5  | one way (though 2 pairs often used for mutual authentication) | slow    | private key, not shared                                                              | Not when used for authentication, yes if used to encrypt contents to prove origination and integrity | Authentication, message integrity | - digital signatures - Public Key Infrastructure (PKI) - initial handshake for SSH, TLS, end-to-end encryption - signed  artifacts |
| Symmetric    | two way                                                       | fast    | shared secret                                                                        | yes                                                                                                  | privacy                           | Data at rest - messages after initial handshake for SSH, TLS, end to end encryption                                                |



#### 3. GitHub Actions are actually very scary
- [Example exploits, including a reverse shell](https://cycode.com/blog/github-actions-vulnerabilities)
- [Any maintainer can change a branch or tag ](https://julienrenaux.fr/2019/12/20/github-actions-security-risk/)

1. Can you spot the foothold  in these examples?

```
# by Alex Ilgayev, Cycode, https://cycode.com/blog/github-actions-vulnerabilities/

name: Demo vulnerable workflow

on:
  issues:
    types: [opened]

env:
  # Environment variable for demonstration purposes
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

jobs:
  vuln_job:
    runs-on: ubuntu-latest

    steps:
     # Checkout used for demonstration purposes
      - uses: actions/checkout@v2
    
      - run: |
         echo "ISSUE TITLE: ${{github.event.issue.title}}"
         echo "ISSUE DESCRIPTION: ${{github.event.issue.body}}"

      - run: |
         curl -X POST -H "Authorization: Token ${{ secrets.BOT_TOKEN }}" -d '{"labels": ["New Issue"]}' ${{ github.event.issue.url }}/labels
```


```yml
# by Nathan Davidson, https://nathandavison.com/blog/github-actions-and-the-threat-of-malicious-pull-requests

name: my action
on: pull_request_target

jobs:
  pr-check: 
    name: Check PR
    runs-on: ubuntu-latest
    steps:
      - name: Setup Action
        uses: actions/checkout@v2
        with:
          ref: ${{github.event.pull_request.head.ref}}
          repository: ${{github.event.pull_request.head.repo.full_name}}
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: some command
        run: some_command
        env:
          SOME_SECRET: ${{ secrets.SOME_SECRET }}
```

2. Things to avoid:
	- [Untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/)
	- GitHub Actions that push to the default branch, or that make and approve PRs
	- `pull_request_target` - runs in the context of the base repo!
		- [”Preventing pwn requests”](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
	- The `run` step
	
3. Things to do
	Review [Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) best practices written by GitHub. There are a lot. Here are some of the highest impact:
	- Whitelist actions![Pasted image 20240828142237.png]
	- Require approval for outside collaborators (fork PRs) ![Pasted image 20240828142455.png]
	- Be wary of any integrations that run Actions on forks
		- For example, [CircleCI](https://nathandavison.com/blog/shaking-secrets-out-of-circleci-builds)
	- Save credentials as a Repository or Organization Secret
	- Specify [minimum permissions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token)for the `GITHUB_TOKEN`
	- Declare untrusted input as env variables 
	- Review 3rd party actions and pin them to a SHA

```
# by Alex Ilgayev, Cycode, https://cycode.com/blog/github-actions-vulnerabilities/

- env:
  TITLE: ${{github.event.issue.title}}
  DESCRIPTION: ${{github.event.issue.body}}
  
run: |
  echo "ISSUE TITLE: $TITLE"
  echo "ISSUE DESCRIPTION: $DESCRIPTION"	
```
	
#### 4. The top 4 initial vectors in 2023 were: exploit, phishing, prior compromise, and stolen credentials. 
- What does that mean for devs?

![Pasted image 20240826215713.png]
[Google Mandiant Trends 2024](https://cloud.google.com/security/resources/m-trends?hl=en)

---
## II. A basic checklist for secure development
#### In your development process
- [ ] Do a STRIDE [threat model](https://en.wikipedia.org/wiki/STRIDE_model) for every new feature.

![Pasted image 20240828190015.png]
- [ ] Establish logging standards as part of code quality standards.
- [ ] Do regular threat models of your CI/CD and publishing lifecyle
#### In your source code management
- [ ] Automate pre-merge and pre-deploy scans for:
	1. open source libraries, (“Software Composition Analysis” or SCA)
	2. static analysis (“Static Application Security Testing” or SAST)
	3. secrets
	4. container images 
	5. debug flags, dev/test packages, or anything else that needs to be flipped when going to production 
- [ ] Automate patch management for internal and 3rd party dependencies,
- [ ] Require PR reviews for any changes to production code.

#### While coding
- [ ] Vet anything you import from a third party.
	1. [Snyk Advisor](https://snyk.io/advisor/python)
	2. [GitHub Vulnerability Advisories](https://github.com/advisories)
	3. Docker Hub, [for example](https://hub.docker.com/layers/library/ubuntu/rolling/images/sha256-99b4265f3384d072acdc008cdb971a6b89869faa8c5e31580d7ed3532750ae00?context=explore)
	4. *Read the source code!
	5. Prefer pinning SHAs for anything third party, avoid floating tags or releases like `latest`
		1. Especially [GitHub Actions](https://securitylab.github.com/resources/github-actions-building-blocks/) 
	6. Read the source code!
- [ ] Incorporate threat model mitigations into your tests.

#### Apply to all of the above
- [ ] Whitelist as much as possible (“deny by default”) 
	- Unknown IPs blocked by default
	- Endpoints behind auth by default
- [ ] Use the principle of least privilege
	- Use service accounts for service credentials, limit credential scopes, use dedicated credentials for each service
	- Limit privileges of your own individual accounts. Consider just-in-time promotions for sensitive actions and make sure they are logged somewhere.
	- Design your software for least privilege.
- [ ] Minimize surface area
	- Simplify architecture to minimize public exposure 
		- CAVEAT: beware “walled gardens”
	- Simplify code
	- Simplify processes to limit possible actions
	- Decomm unused services ruthlessly 
	- Don’t rely on “security through obscurity”

---

## III. What new devs should learn

- [ ] Familiarize yourself with the most recent OWASP Top 10 (as of this writing, [2021](https://owasp.org/Top10/A11_2021-Next_Steps/))
- [ ] Jump around the labs on [Portswigger’s Web Security Academy](https://portswigger.net/web-security) 
	- Start with Access Control, Authentication, SQL Injection, OAuth, and JWT
- [ ] Practice [threat modeling](https://en.wikipedia.org/wiki/STRIDE_model) whenever you can
- [ ] *Focus on craft: clean code, design patterns, good documentation
- [ ] Learn the vocabulary of security properties
	- [STRIDE](https://en.wikipedia.org/wiki/STRIDE_model) plus [least privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege), [deny by default](https://en.wikipedia.org/wiki/Principle_of_least_privilege) 
	- [Others from the OWASP development guide](https://github.com/OWASP/DevGuide/blob/master/02-Design/01-Principles%20of%20Security%20Engineering.md)
![Pasted image 20240828190015.png]

---
## IV. What experienced devs can do to keep growing

- [ ] Include security criteria in acceptance tests and requirements.
- [ ] Push your threat models into blind spots
	- Edges of scope and ownership, integration points
	- Any areas assumed “safe” (beware the walled garden!)
	- Legacy or inherited code
	- Insider threats
- [ ] Advocate for customer-facing security features in the products you build
	- Audit logs (useful ones!)
	- Access notifications.
	- Fine grained, time limited permissions.
	- Secret verification APIs.
- [ ] If you have a security team: ask to access pen-test findings, bug bounty awards, incident retros.
- [ ] Allocate some of your media consumption to security content from thoughtful sources. 

## V. Team culture is core to your security posture

- Do team members feel safe enough to admit mistakes or gaps in knowledge?
- If one person brings up a concern, does the team take it seriously?
- Do senior members model time off, taking sick leave, and reasonable hours?
- Do junior engineers receive training, feedback, and mentoring?
- Does your management pad your team’s roadmap to allow adequate time for quality work?
- Does the hiring process select for diverse backgrounds, skill sets, and experience?

---
## Resources

#### Offensive training
- [Portswigger academy](https://portswigger.net/web-security)
- [OWASP “Damn Vulnerable” web apps](https://github.com/OWASP/OWASP-VWAD)
#### References
- [OWASP top 10 2021](https://owasp.org/Top10/A11_2021-Next_Steps/)
- [OWASP Cheat sheets](https://cheatsheetseries.owasp.org/index.html)
	- [here’s one for password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OAuth 2.0/ OIDC concepts illustrated by Okta](https://developer.okta.com/docs/concepts/oauth-openid/)
-  [Threat Modeling Beginner’s Guide](https://shostack.org/resources/threat-modeling)
#### Books
- [Threat Modeling: Designing for Security, Adam Shostak](https://shostack.org/books/threat-modeling-book)
- [Security Engineering: Building Dependable Distributed systems](https://www.amazon.com/Security-Engineering-Building-Dependable-Distributed/dp/1119642787)
- [Julia Evans’s Wizard Zines](https://wizardzines.com/), esp. if you work mostly at the app layer: 
	- Networking
	- Linux
	- DNS
	- Containers
### Podcasts
- [Absolute Appsec](https://absoluteappsec.com/)
- [Darknet Diaries](https://darknetdiaries.com/)
- [Malicious Life](https://malicious.life/)
- [Human Factor Security](https://humanfactorsecurity.co.uk/podcast-2/) Social engineering  (archive)
- [Real Python]() - Python specific, some security coverage

### Newsletters
- [tldr;sec](https://tldrsec.com/)
- [Schneier on security](https://www.schneier.com/crypto-gram/)

### Ghost stories  
- If you think you’re immune to social engineering
	- [The Cut’s financial writer, Caroline Cowles, talks about losing $50K to a scam](https://www.thecut.com/article/amazon-scam-call-ftc-arrest-warrants.html)
	- [Cory Doctorow describes getting phished](https://pluralistic.net/2024/02/05/cyber-dunning-kruger/#swiss-cheese-security) 
- If you’re skeptical of insider threats
	- [Timeline of the xz backdoor](https://research.swtch.com/xz-timeline)
