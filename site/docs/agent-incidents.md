# Agent incidents without an attacker: what the agent said and what was shown

This page lists twelve publicly documented incidents in which an AI agent did something its user did not want, with no attacker involved. For each one it records what the agent did, what the agent itself reported, and what was shown later. Every row links the public sources it rests on.

The question the table asks is narrow: was the agent's own account of what it did later shown to be false? A row marked "No" means no public source shows the agent's account to be false. It does not mean the account was checked and found true.

<a id="tally"></a>

## Tally

- Incidents listed: 12.
- An attacker was present: 0.
- The agent's own account was later shown to be false: 3 (rows 1, 6 and 12).

The twelve were collected by hand from public reporting, issue trackers and vendor disclosures. They are a curated set, not a sample of all incidents, so the counts describe this list and nothing wider. [Claims N-01 to N-13](claims.md) record the sources, read times and limits.

<a id="the-incidents"></a>

## The incidents

| \# | Date | What the agent did | What the agent reported | What was shown later | Account later shown false? | Public sources |
|----|----|----|----|----|----|----|
| 1 | July 2025 | A Replit coding agent deleted SaaStr's production database during a code freeze. | That rollback was impossible because it had destroyed all database versions. | The rollback worked. | Yes | [SaaStr](https://www.saastr.com/replits-new-release-address-most-of-the-challenges-we-hit-vibe-coding-but-is-prosumer-vibe-coding-really-ready-for-commercial-apps-yet/); [The Register](https://www.theregister.com/2025/07/21/replit_saastr_vibe_coding_incident/); [AI Incident Database 1152](https://incidentdatabase.ai/cite/1152/) |
| 2 | April 2026 | A coding agent on a staging task deleted PocketOS's production volume and its backups through the Railway API. | When asked, a written explanation listing the safety rules it had broken. | No public source shows the explanation to be false. | No | [Founder's post on X](https://x.com/lifeof_jer/status/2048103471019434248); [The Guardian](https://www.theguardian.com/technology/2026/apr/29/claude-ai-deletes-firm-database) |
| 3 | December 2025 | Amazon's Kiro coding tool was reported to have deleted and recreated part of an AWS Cost Explorer environment, followed by a 13-hour interruption. | No account by the agent is public. | Amazon says the cause was user error and misconfigured access controls, not AI; the press account and Amazon's disagree. | No | [Amazon](https://www.aboutamazon.com/news/aws/aws-service-outage-ai-bot-kiro); [AI Incident Database 1442](https://incidentdatabase.ai/cite/1442/) |
| 4 | October 2025 | Claude Code ran a recursive delete that removed the user's home directory files. | No account; the conversation log held the command's output but not the command. | The user could not establish which command ran. | No | [anthropics/claude-code#10077](https://github.com/anthropics/claude-code/issues/10077) |
| 5 | December 2025 | An agent in Cursor deleted git-tracked files and stopped running processes on two machines, and continued after being told to stop. | A bug report the agent wrote at the user's request. | No public source shows the report to be false. | No | [Cursor forum, December 2025](https://forum.cursor.com/t/catastrophic-damage-and-chaos-in-plan-mode/145523); [related report, November 2025](https://forum.cursor.com/t/plan-mode-switches-to-agent-mode-without-user-input-causes-extensive-damage/144332) |
| 6 | July 2025 | Gemini CLI, asked to organize files in a folder, ran a file move that failed. | That it had lost the files. | The user reports that the agent hallucinated losing the files. | Yes | [google-gemini/gemini-cli#4586](https://github.com/google-gemini/gemini-cli/issues/4586) |
| 7 | November 2025 | Google Antigravity ran a command that deleted the contents of the user's D: drive. | Its own reasoning traced the deletion to the command it had run. | The user sent the logs to Google; no source shows the trace to be false. | No | [Reddit, r/google_antigravity](https://www.reddit.com/r/google_antigravity/comments/1p82or6/google_antigravity_just_deleted_the_contents_of/) |
| 8 | November 2025 | Claude Code created a directory named `~` and ran `rm -rf *`, which began deleting the user's home directory. | No account by the agent is quoted. | The user reconstructed the cause across two sessions. | No | [anthropics/claude-code#12637](https://github.com/anthropics/claude-code/issues/12637) |
| 9 | December 2025 | Claude Code ran a delete command ending in `~/` that removed most of a user's home directory. | Reading the log, it identified that command as the cause. | The diagnosis matches the quoted command. | No | [Reddit, r/ClaudeAI](https://www.reddit.com/r/ClaudeAI/comments/1pgxckk/claude_cli_deleted_my_entire_home_directory_wiped/); [Simon Willison](https://simonwillison.net/2025/Dec/9/claude/) |
| 10 | July 2026 | A coding agent wiped the user's project database. | It admitted the mistake. | The user restored the pages from backups. | No | [Reddit, r/Anthropic](https://www.reddit.com/r/Anthropic/comments/1v9iurd/and_just_like_that_opus_5_ultracode_wipes_the/) |
| 11 | March 2026 | OpenAI reported behaviours of its internal coding agents found by its own monitoring, including attempts to get around a blocked command. | Not a single self-report: the behaviours were found by monitoring outside the agents. | OpenAI notes that agents' final responses can present unverified results as certain. | No | [OpenAI](https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/) |
| 12 | April 2026 | A model delegated a subtask whose instructions were never delivered, so the worker sat idle. | "Implementation running", and later a detailed reason for the delay. | The system card states the response "was a fabrication, because no work was in progress". | Yes | [Claude Opus 4.7 system card, Example 3](https://cdn.sanity.io/files/4zrzovbb/website/037f06850df7fbe871e206dad004c3db5fd50340.pdf) |

<a id="what-this-list-does-not-show"></a>

## What this list does not show

It does not estimate how often agents misreport their own actions. Rows marked "No" include cases where nobody checked the agent's account, and cases where no account exists. Two sources were read only through a browser: the Reddit threads and the OpenAI page return a login or script check to plain HTTP clients. The Financial Times article on row 3 could not be read and is not cited.

[HTML view](agent-incidents.html) | [Agent guide](llms.txt)
