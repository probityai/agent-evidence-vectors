# Guard replay over real coding-agent history

One Ratchet guard, `no-force-push-main`, tested by replay over the operator's own Claude Code session transcripts.
A guard is a small rule that checks each tool call before it runs. Replay means rerunning recorded past
conversations through the rule, in Ratchet's sandboxed guard runtime. No model call is made: each recorded tool
call is checked as if the guard had been installed before it ran.

| Measure | Value |
|---|---|
| Sessions | 13,739 |
| Tool calls checked | 632,126 |
| Guard fires | 6, all real force-pushes to a main branch; 0 false alarms |
| Checker crashes | 0 |
| Check time | 552 s on one worker at reduced priority (about 1,145 checks per second) |

Every fire gives the reason "force push to main rewrites shared history; push a branch and open a pull request
instead". The six fires are the same six tool calls the first run flagged as real force-pushes. Unreadable
transcript files (1) and malformed lines (118) are counted and skipped. The transcript set grew by 27 sessions
and 2,934 tool calls between the two runs, as sessions kept being recorded; none of the new calls fired.

## History

The first run, with the previous version of the guard, checked 13,712 sessions and 629,192 tool calls and
fired 7 times: 6 real force-pushes to a main branch and 1 false alarm, with 0 checker crashes, in 393 s on four
workers (about 1,600 checks per second). The false alarm was an agent writing a document through a Python
heredoc; the document's text named a force-push command, and nothing was pushed. The guard now reads a heredoc
body as data unless it is fed to a shell as a script, counts `--mirror` as a force (git force-updates every
remote branch under it), and ignores dry runs. The second run above is that version.
