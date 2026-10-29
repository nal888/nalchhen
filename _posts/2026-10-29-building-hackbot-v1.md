---
title: "Building Hackbot v1: a practical starting point"
date: 2026-10-29 00:00:00 +1100
description: "A practical starting point for building a supervised hackbot for bug bounty research."
categories: [AI Security, Bug Bounty]
tags: [ai, hackbot, bug-bounty, agents, automation]
pin: true
toc: true
image:
  path: /assets/hackbot-blog/blog-cover.png
  alt: Building Hackbot v1
---

<style>
.content figure.screenshot { margin: 1.5rem 0 1.9rem; padding: .75rem; border: 1px solid var(--main-border-color); border-radius: 5px; background: var(--card-bg); }
.content figure.screenshot img { display: block; max-width: 100%; height: auto; border: 1px solid var(--main-border-color); border-radius: 3px; }
.content figure.screenshot figcaption { margin: .6rem .2rem 0; font-size: .82rem; line-height: 1.45; opacity: .75; }
.content .reading-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); column-gap: 1.6rem; list-style: none; padding: 0; margin: 0 0 1.5rem; }
.content .reading-list li { min-width: 0; padding: 0; margin: 0; border-bottom: 1px solid var(--main-border-color); }
.content .reading-link { display: grid; grid-template-columns: 104px minmax(0, 1fr); gap: .9rem; align-items: start; padding: 1rem 0; text-decoration: none; }
.content .reading-link img { display: block; width: 104px; height: 55px; object-fit: contain; border: 1px solid var(--main-border-color); border-radius: 3px; }
.content .reading-copy > span { display: block; }
.content .reading-source { font-size: .75rem; opacity: .7; margin-bottom: .25rem; }
.content .reading-title { font-size: .96rem; line-height: 1.35; font-weight: 600; }
.content .reading-note { font-size: .79rem; line-height: 1.45; opacity: .7; margin-top: .3rem; }
.content .reading-link:hover .reading-title { text-decoration: underline; }
@media (max-width: 660px) { .content .reading-list { grid-template-columns: 1fr; } }
</style>

By now everyone knows AI is powerful, but it depends on how you use it—and that’s the part I find interesting. I wanted to see how far I could get building an agent for bug bounty.

The rough idea was for that agent to understand an application, follow a question, and show me evidence I could check myself.

I’m building this in my spare time while at university, and I’m still learning. So far, my results have only been duplicates and informational findings. I thought I’d share how I’m building it anyway, in case it’s useful to someone else experimenting with AI for bug bounty.

For now, take what’s useful and try it on a small task of your own. You don’t need to copy my whole setup. A later post could go further into how I check results and the harness—the setup that runs checks and records their output.

## What you need

1. **A terminal agent.** I’m using Claude Code here. Codex is another option. The terminal agent gives the model access to the workspace and the tools you allow.
2. **A workspace.** I use a folder in my Kali VM for the files and notes. Another machine with a terminal works too.
3. **An instruction file.** Use `CLAUDE.md` for Claude Code or `AGENTS.md` for Codex. We’ll start with a few rough notes.
4. **Some saved JavaScript.** This post uses local files to look at how the agent works. I’ll show how I saved them with a browser extension.

For this first post, I’m starting with instructions, a JavaScript example and a few things I changed after watching the agent work.

## Install a terminal agent

Choose Codex or Claude Code. On Linux or macOS, the [Codex CLI guide](https://learn.chatgpt.com/docs/codex/cli) gives:

```sh
curl -fsSL https://chatgpt.com/codex/install.sh | sh
```

Or follow the [Claude Code quickstart](https://code.claude.com/docs/en/quickstart):

```sh
curl -fsSL https://claude.ai/install.sh | bash
```

Check the one you installed with `codex --version` or `claude --version`. We will start it from the workspace after making its instruction file.

## Make the workspace

Start with a folder for the hackbot itself. There is no target in it yet:

```sh
mkdir -p hackbot
cd hackbot
```

## Start with CLAUDE.md or AGENTS.md

Open your `hackbot` folder in VS Code and create `CLAUDE.md` for [Claude Code](https://code.claude.com/docs/en/memory), or `AGENTS.md` for [Codex](https://learn.chatgpt.com/docs/agent-configuration/agents-md). The agent reads this file for instructions about how to work. I’m using Claude Code here.

### Start with what you don’t want your hackbot to do

First, I like to think about what I **don’t want** the hackbot to do. I find that easier to start with. For example: don’t go outside the program’s scope, don’t run DoS or brute force, and don’t delete my test accounts.

Some of these come from ordinary bug bounty rules. Others come from watching the agent work. For example, I added the token and session notes after seeing an authorization check change the test setup and lose track of which cookie belonged to which account.

Write a few ideas like that in your own words. You don’t need perfect English or every rule figured out yet. Here is what my first notes looked like:

<figure class="screenshot">
  <a href="/assets/hackbot-blog/step3-rough.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/step3-rough.png" alt="Full VS Code screenshot showing rough CLAUDE.md notes and the Claude Code terminal session" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>The first file was just a few rough ideas. Click the image to see it full size.</figcaption>
</figure>

Save the file, open the terminal in VS Code, and start `claude` or `codex` from that folder. Ask it to look at your notes and help with them. I typed “improve claude.md” here, but you can just explain what you want in your own words and talk through it together.

<figure class="screenshot">
  <a href="/assets/hackbot-blog/step3-revised.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/step3-revised.png" alt="Full VS Code screenshot showing the revised CLAUDE.md and Claude Code explaining its changes in the terminal" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>Claude cleaned up the wording, organized the notes, and suggested a few additions.</figcaption>
</figure>

Claude cleaned up my wording and added a few things. This is my usual Kali workspace, so it already had some context from my setup. Your result may look different.

Read what changed and tell it if something doesn’t match your idea. As you go, you can add what you want the hackbot to do too. The file can grow with what you learn from using it.

## Tell the agent how to check the code

I want to give the hackbot a more reliable way to check things. Sometimes the agent does a few searches and gives an answer that sounds complete, but it may have missed something. One thing I tried was asking it to use AST parsing when looking at JavaScript. I started by putting that instruction in `CLAUDE.md`.

AST stands for abstract syntax tree. A parser turns code into a tree that shows how the parts fit together. Here is a small example:

```js
// greet("Sam")
greet("Sam");
```

A text search for `greet` finds both lines. A script reading the AST can identify just the actual call. A simple picture of that call looks like this:

```text
Function call
├── Name: greet
└── Argument: "Sam"
```

Now the script can check the function name and its arguments directly. That is why an AST can help when we want to ask questions about the code’s structure.

### Example 1: Let Claude choose how to work

**Save the files.** I use [Resources Saver for Chrome](https://chromewebstore.google.com/detail/resources-saver/nlfcijlhljpenllloeheihmhoobeefpc) to save the files loaded by a page, including its JavaScript. Here I opened YouTube, opened DevTools, selected **Resources Saver**, and clicked **Save All Resources**.

<figure class="screenshot">
  <a href="/assets/hackbot-blog/resources-saver.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/resources-saver.png" alt="YouTube open beside the Resources Saver panel in Chrome DevTools" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>Saving the resources loaded by the page. Click to see the full image.</figcaption>
</figure>

This downloaded `www.youtube.com.zip` ([download screenshot](/assets/hackbot-blog/resources-download.png)). I moved it into `hackbot/js-file/`. These are just the files collected from that page. We’ll use the same saved files for both runs.

**Try a normal request first.** I asked Claude to look through the saved JavaScript, find message listeners, and explain the checks it could see. I hadn’t added the AST instruction yet.

```text
look through the js in js-file and find postmessage listeners
show what origin and source checks they use and what looks
properly checked or unclear or needs more review
```

<figure class="screenshot">
  <a href="/assets/hackbot-blog/js-first-prompt.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/js-first-prompt.png" alt="VS Code showing the saved ZIP in js-file and the first request in the Claude terminal" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>The ZIP is in js-file. The request says what I want to know, without choosing a search method. Click to see the full image.</figcaption>
</figure>

Claude extracted the ZIP and used `grep` to search the files for matching text. It then wrote a small Python script using regex, which also matches text patterns. The script showed the code around each match. If Claude saw another function name, it searched for that name and read more code to see what it did.

<figure class="screenshot">
  <a href="/assets/hackbot-blog/js-regex-tracing.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/js-regex-tracing.png" alt="Expanded Claude command showing Python regex searches and slices of surrounding text" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>The expanded command shows how Claude followed references: search for a name, then print nearby code. Click to see the full image.</figcaption>
</figure>

The searches helped Claude find code to read. One thing I noticed was that the script checked whether `.origin` or `.source` appeared near a match. Those words could belong to another function, so Claude still had to follow the code to see how they were used. I also wanted to know which listeners the search might have missed.

### Example 2: Same prompt, updated CLAUDE.md

For this comparison, I kept the same saved files and the same request, and changed the instructions in `CLAUDE.md`. These are the instructions shown in the screenshot:

```markdown
## JavaScript analysis

- For JavaScript analysis or review, always start with AST parsing. Never use grep, regex, or text snippets as the first analysis pass or as a substitute for AST checks.
- Use @babel/parser, @babel/traverse, and @babel/types. Resolve local references with path.scope.getBinding(name). Keep ambiguous references unresolved rather than matching names across the file.
- Account for JavaScript under other file extensions and inline scripts. Report anything the checker cannot process.
- Save and reuse the checker. Test with assertions for matching and non-matching examples, including repeated names in different scopes.
- Separate script results from your interpretation. Report checked, failed, skipped, and unresolved cases. If AST analysis cannot run, stop the analysis and explain the blocker. Don’t silently fall back to text searches or claim complete coverage.
```

I tried a few versions as I watched the runs. This is one of the later versions, with more detail about parsing, local references and coverage:

<figure class="screenshot">
  <a href="/assets/hackbot-blog/js-ast-instructions.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/js-ast-instructions.png" alt="VS Code showing the JavaScript analysis instructions in CLAUDE.md and the same request ready in a fresh Claude session" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>The method is in CLAUDE.md. The request in the terminal stays the same. Click to see the full image.</figcaption>
</figure>

I started a fresh session and sent the same request. I didn’t need to mention AST again because it was already in `CLAUDE.md`. Then I opened the commands to see whether Claude actually followed the instruction.

In that run, Claude used Babel, wrote a checker and tested it with 26 assertions. But the first pass still missed three files containing JavaScript because their names ended in `.html`. It treated them as HTML, found no inline scripts, and moved on. Later in the run, it noticed the problem and parsed those files separately as JavaScript.

Here is the summary Claude gave me after that run:

<figure class="screenshot">
  <a href="/assets/hackbot-blog/js-ast-run-summary.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/js-ast-run-summary.png" alt="Claude session summary describing Babel AST analysis, 26 test assertions and the correction for JavaScript files saved with an HTML extension" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>Claude’s summary includes the correction for the .html files. The labels below are its assessment; I still need to check the code behind them. Click to see the full image.</figcaption>
</figure>

After that run, I wanted to see which files the checker had covered, the code behind each observation and anything it couldn’t work out. The missed `.html` files gave me something specific to fix.

## Move repeatable checks into code

The instructions were a useful starting point. But across these runs, Claude kept writing and changing its checker. That meant the same request could end up using different code, with different gaps.

I want to move as much of that repeatable work into code as I can. Instead of asking the agent to build the checker again, I can give it a saved tool to run. When I find a problem, I fix that tool and add a small test so I can check the same case next time. For the `.html` problem, that means testing both a real HTML page and a JavaScript file with an `.html` name.

You can start with one script:

1. Save the part you want to reuse, such as parsing local files and listing function calls.
2. Try small examples where you know what should appear in the result, and what should not. A call inside a comment should not count as a real call.
3. Make the script report what it processed and what it could not handle. Keep the full result in a file so the agent can read it.

Here is a small example from my own saved tool. I’m showing the report to explain the idea; the tool and its test files aren’t included in this post. I gave it five test inputs, including broken JavaScript, JavaScript saved with an `.html` extension and a page referring to a script that wasn’t downloaded:

| Input | Result | What happened |
| --- | --- | --- |
| `broken.js` | Failed | The parser could not read the syntax. |
| `bundle.html` | Checked | Parsed the JavaScript despite the file extension. |
| `data.json` | Skipped | Recognized it as JSON data. |
| `page.html` | Partial | Read the inline JavaScript; the external script was not loaded. |
| `unknown.js` | Checked | Finished the structural checks, with unresolved calls still recorded. |

The overall result was **partial**. The tool saved the details in JSON and a shorter Markdown report. In this report, “checked” means the script finished its selected checks. I still need to review the unresolved calls and skipped files. Those gaps stay in the report for the agent to pick up later.

`CLAUDE.md` or `AGENTS.md` can then tell the agent which tool to run and how to use its report. The code handles the repeatable part, and the agent helps explain the results and decide what needs a closer look.

This is what I mean by making that part more deterministic: the same tool runs the same rules on the same input. When it misses something, I can keep that example, fix the tool and run it again.

AST is one example for JavaScript analysis. The same idea can help with other parts of web testing and bug bounty work too:

- **Looking at reflected input.** Sometimes the agent sees a parameter reflected in a response and jumps straight to calling it a vulnerability. An HTML parser can help record where that input appears, such as in text, an attribute or a script element. The agent can point to that location and explain what happened. If reflection is all it observed, the note should say that, with any further questions left open.
- **Making authorization expectations explicit.** For a feature with viewer and editor roles, write down what each role should be allowed to do. Keep the expected behavior, observed result and evidence together in a matrix. That gives the agent a consistent way to review the results and helps you spot missing cases. Start with permissions you know; leave uncertain ones as questions. [OWASP describes this approach](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html).
- **Comparing responses consistently.** Two saved responses might differ in one useful field and dozens of timestamps or request IDs. A comparison tool can show the exact changes for the agent to examine. Keep the originals and record any fields you exclude from the comparison. [Burp Comparer](https://portswigger.net/burp/documentation/desktop/tools/comparer) is one existing tool to explore.

These give the agent something concrete to work with: the location of reflected input, the expected permissions or the differences between responses. You can start with one part of your own testing, find a method or tool that helps, and check how the agent uses its results.

## Context engineering

Imagine you’re looking at a web application with several large JavaScript files, lots of requests and different user accounts. Your agent starts reading the JavaScript, writes a script to check it, fixes the script, then moves on to the traffic. You still want it to remember the original question, what it already checked and what needs another look.

If all of that happens in one session, the conversation fills with code, tool output and old attempts. For example, the parser might fail on one file early on. Much later, you ask whether the JavaScript review is finished. Does the agent still know that file was skipped, or has that detail disappeared into a summary saying “JavaScript reviewed”?

<figure class="screenshot">
  <a href="/assets/hackbot-blog/context-problem-solution.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/context-problem-solution.png" alt="Problem and approach compared: a skipped JavaScript file can disappear from a crowded session's summary; a focused worker saves the full report and returns the unresolved gap to the coordinator." style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>An example of a detail we want to keep: the file that was never checked. A saved report keeps that gap available to review. Keeping useful notes helps with a single agent too.</figcaption>
</figure>

Having room in the context window doesn’t mean the agent will use every detail reliably. Long contexts can make relevant information harder to retrieve. Compaction helps by summarizing the conversation, but that summary can also leave out something important. [Anthropic’s context engineering article](https://www.anthropic.com/research/effective-context-engineering-for-ai-agents) explains these tradeoffs.

This is where context engineering comes in: deciding what the agent needs to see now, what should stay in files and how it can find those details again. I think this is an important part to learn if you want to take this further. Writing a good `CLAUDE.md` is a start; keeping the agent focused as the work grows matters too.

So I don’t want the main session to do all the detailed work itself. I use it as the coordinator: keep the overall picture, the open questions and the decisions, and give workers smaller jobs with their own context. It still investigates by comparing results, checking evidence and deciding what to ask next.

The diagram below shows how I’m thinking about extending this to more jobs. You don’t need all these roles for the JavaScript experiment above.

<figure class="screenshot">
  <a href="/assets/hackbot-blog/coordinator-workers-v5.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/coordinator-workers-v5.png" alt="Coordinator above Recon, JavaScript and Exploiter workers, with Validator below and Target at the bottom. Labeled arrows distinguish assignments, returned evidence and validation checks." style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>The coordinator assigns work, reviews what the workers return and requests validation when needed.</figcaption>
</figure>

I would add these roles as I need them. The coordinator gives a worker one question and the relevant context, then reads its result before deciding what comes next. Detailed notes stay in files, with links back to the original evidence.

For the JavaScript example, the worker gets the saved files, the analysis tool and one question. It can work through the detailed output in its own session, save the full report, then return what was checked, what remains unclear and the relevant file locations. The coordinator can use that result without carrying every page of parser output. The summary includes file locations so the coordinator can open the original evidence when it needs to check something.

The validator in the diagram is mainly code. I took inspiration from [James Kettle’s HTTP Terminator research](https://portswigger.net/research/can-ai-do-novel-security-research#making-iteration-viable), especially the idea of moving responsibility from AI into code as the system improves. In my setup, Python code produces the verdict from the checks, control results and repeatability rules. I still have to test those checks and review the evidence going into them. If the setup breaks or the results are too noisy, the outcome can stay inconclusive. I’ll leave the implementation for another post.

You can start with just the main session and one worker. Keep the question small, include the context it needs and ask for evidence and gaps back. Then see whether the handoff actually helps before adding more roles.

There’s more to explore here too: how you keep notes, when the agent loads files and how much output your tools return. If this interests you, read the [context engineering article](https://www.anthropic.com/research/effective-context-engineering-for-ai-agents) and [how Anthropic built its multi-agent research system](https://www.anthropic.com/research/multi-agent-research-system). Try the ideas on a small task and look at what your own agent keeps, misses or has to read again.

## Build skills from sources you trust

Think of a skill as a reusable way to show the agent how you want a particular job done. It can be a short workflow, guidance for reading a report, or instructions with supporting scripts. A few useful instructions can be enough to start. The [Codex](https://learn.chatgpt.com/docs/build-skills) and [Claude Code](https://code.claude.com/docs/en/skills) guides explain the format.

### Give it the source and the purpose

I’d recommend reading the relevant chapters or report yourself too. Choose something with an explanation and evidence you can follow. Think about where the idea applies, and ask the agent to help with parts you don’t understand. That makes it easier to check what ends up in the skill.

I sometimes start a fresh session, give the agent a book and explain that the skill is for bug bounty work. I want something useful during the work: clear references, examples and reusable helpers where they make sense. Without that context, “make a skill from this book” can turn into little more than a chapter summary.

Use the skill-creation helper to organize it: [`$skill-creator` in Codex](https://learn.chatgpt.com/docs/build-skills#create-a-skill), or Claude’s [`skill-creator` plugin](https://code.claude.com/docs/en/skills#run-evals-with-skill-creator). You can explain the idea in rough notes and work through it together, like we did with `CLAUDE.md`.

### Official docs: my CVSS example

CVSS stands for Common Vulnerability Scoring System. For my skill, I gave the agent the PDF from [FIRST’s CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document). The agent explains its metric choices using the evidence, then a script calculates the score. I check the metric choices against the evidence before using the score.

That’s the same idea as the JavaScript tool above: move the repeatable part into code.

<figure class="screenshot compact-figure" style="max-width:540px;margin:22px auto;">
  <a href="/assets/hackbot-blog/skill-cvss-source.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/skill-cvss-source.png" alt="FIRST CVSS v3.1 specification page, with a red box around the versioned specification and a red arrow pointing to its PDF download" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>The specification and PDF I used. Click to see the full screenshot.</figcaption>
</figure>

### Books: a starting point for a skill

For GraphQL, I’ve used [Black Hat GraphQL](https://nostarch.com/black-hat-graphql). I want the useful explanations, conditions and examples to survive in the skill. Relevant code examples can help too, but I check what they do and whether they work. Longer notes can stay in references instead of filling `SKILL.md`.

<figure class="screenshot compact-figure" style="max-width:480px;margin:22px auto;">
  <a href="/assets/hackbot-blog/skill-graphql-source.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/skill-graphql-source.png" alt="Publisher page for Black Hat GraphQL, showing the book cover and title" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>One book I used as source material.</figcaption>
</figure>

### Bug bounty reports and older research

I also collect bug bounty reports and write-ups. The screenshot below is my collection. I care more about what a report teaches than how many I can save: what caused the bug, which conditions mattered and how the researcher showed the impact.

A useful report can become reference material for a skill, with its explanation and evidence kept together. That gives me something to learn from and the agent something to refer back to when it sees similar behavior. An older paper or an interesting piece of research can be useful in the same way.

<figure class="screenshot compact-figure" style="max-width:540px;margin:22px auto;">
  <a href="/assets/hackbot-blog/skill-report-collection.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/skill-report-collection.png" alt="My collection of bug bounty reports and write-ups, organized by topic with source links, saved copies and review notes" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>My collection of bug bounty reports and write-ups. I keep the sources and notes so I can return to the useful ones.</figcaption>
</figure>

When reading a report, note anything you can’t follow or that needs more evidence. Work through those gaps before using it in a skill. Keep a link to the source, try the skill on a small example and check what it produces.

<figure class="screenshot compact-figure" style="max-width:600px;margin:22px auto;">
  <a href="/assets/hackbot-blog/skill-from-sources.png" target="_blank" rel="noopener">
    <img src="/assets/hackbot-blog/skill-from-sources.png" alt="A chosen source and purpose go into a fresh agent session using a skill creator, then the resulting skill is tried, checked and improved" style="display:block;width:100%;height:auto;">
  </a>
  <figcaption>Start with a useful source, try the skill on a small example and improve it as you go.</figcaption>
</figure>

## If you already have a target

You can start by giving that target its own folder. In my setup, I keep the program’s scope separate from the general instructions, and keep the current question separate from the detailed work.

I put a [small starter template on GitHub](https://github.com/nal888/hackbot-starter), based on that idea. You can copy the files you want or clone the repo:

```text
targets/TARGET-NAME/
├── CLAUDE.md            scope, rules and account labels
├── AGENTS.md            points to the same target brief
├── APPLICATION.md       what I know about the application
├── NOTES.md             current question, decisions and gaps
├── sessions/INDEX.md    session IDs and transcript locations
└── evidence/            dated notes and saved artifacts
```

Start with the target brief. Add the official scope link, when you checked it, what is allowed, what is excluded and any limits on automation. Use labels for test accounts, not their passwords or tokens. Then put one question in `NOTES.md`. The other files can stay mostly empty until you have something to record.

For the detailed history, I go back to the agent’s session transcript. Record the session ID and where the transcript is saved, then link useful notes to the relevant turn or timestamp. If a worker has its own session, record that too. This lets you see what the agent actually did without copying the whole conversation into your notes. Keep original files alongside those references when the transcript only contains a shortened result.

I picked up the operation-ID idea from [BruteCat’s write-up](https://brutecat.com/articles/hacking-google-with-ai/#refining-the-approach). He had the agent include IDs from recorded API operations in its reports, so he could inspect the actual requests and responses.

The session ID helps me find the conversation. An operation ID, like `op_005`, helps me find a particular request within that run. Save it in the note with a link to the request and response, so you can go back and check what happened.

The repo includes a short README, a blank note template and instructions for saving and reopening sessions in Claude Code or Codex CLI. There’s also a field for operation IDs if your tools provide them. Change the file names and fields to suit how you work.

## Where I’d leave it for now

For a first experiment, I’d stop here: write down how you want the agent to work, give it a small task and look at what it actually does. If it keeps rebuilding the same helper, save that part as a tool. If the conversation fills with unrelated output, try separating one piece of work and keeping its details in a file.

I’m still experimenting with this. A later post could go further into the harness and how I check results, once I have an example worth walking through. For now, take whichever idea is useful, try it on your own small task and see what you would change.

## Further reading and watching

Big shout-out to [Critical Thinking – Bug Bounty Podcast](https://www.criticalthinkingpodcast.io/). It’s where I got most of these ideas and what helped me get started experimenting. These are a few episodes I’d point people to, along with the articles and talks below.

### Critical Thinking episodes

<ul class="reading-list">
  <li>
    <a class="reading-link" href="https://www.youtube.com/watch?v=xZe7bBC17TM" target="_blank" rel="noopener">
      <img src="/assets/hackbot-blog/reading/critical-thinking-178.jpg" alt="" width="104" height="55" loading="lazy">
      <span class="reading-copy">
        <span class="reading-source">Critical Thinking · Episode 178</span>
        <span class="reading-title">BruteCat’s Google hacking story</span>
        <span class="reading-note">The AI part of the conversation with BruteCat.</span>
      </span>
    </a>
  </li>
  <li>
    <a class="reading-link" href="https://www.youtube.com/watch?v=QrVOFD2Xl2A" target="_blank" rel="noopener">
      <img src="/assets/hackbot-blog/reading/critical-thinking-181.jpg" alt="" width="104" height="55" loading="lazy">
      <span class="reading-copy">
        <span class="reading-source">Critical Thinking · Episode 181</span>
        <span class="reading-title">Bug Bounty Singularity</span>
        <span class="reading-note">Joseph and XSSDoctor on building a hackbot.</span>
      </span>
    </a>
  </li>
  <li>
    <a class="reading-link" href="https://www.youtube.com/watch?v=3zs1-KdlQfg" target="_blank" rel="noopener">
      <img src="/assets/hackbot-blog/reading/critical-thinking-186.jpg" alt="" width="104" height="55" loading="lazy">
      <span class="reading-copy">
        <span class="reading-source">Critical Thinking · Episode 186</span>
        <span class="reading-title">Is Sol 5.6 superhuman for bug bounty?</span>
        <span class="reading-note">wp2Shell, model changes and the Gauntlet loop.</span>
      </span>
    </a>
  </li>
</ul>

### Articles and papers

<ul class="reading-list">
  <li>
    <a class="reading-link" href="https://josephthacker.com/hacking/2026/07/01/we-built-a-hackbot.html" target="_blank" rel="noopener">
      <img src="/assets/hackbot-blog/reading/thacker-hackbot.jpg" alt="" width="104" height="55" loading="lazy">
      <span class="reading-copy">
        <span class="reading-source">Joseph Thacker &amp; XSSDoctor</span>
        <span class="reading-title">The Bug Bounty Singularity: Our Hackbot</span>
        <span class="reading-note">Their build story, problems and lessons.</span>
      </span>
    </a>
  </li>
  <li>
    <a class="reading-link" href="https://www.slcyber.io/research/exploit-brokers-pay-500000-for-a-wordpress-rce-i-found-one-with-gpt5-6" target="_blank" rel="noopener">
      <img src="/assets/hackbot-blog/reading/searchlight-wordpress.avif" alt="" width="104" height="55" loading="lazy">
      <span class="reading-copy">
        <span class="reading-source">Searchlight Cyber</span>
        <span class="reading-title">Finding a WordPress RCE with GPT5.6</span>
        <span class="reading-note">The wp2Shell research write-up.</span>
      </span>
    </a>
  </li>
<li>
<a class="reading-link" href="https://www.yeswehack.com/learn-bug-bounty/llm-series-claude" rel="noopener" target="_blank">
<img alt="" height="55" loading="lazy" src="/assets/hackbot-blog/reading/yeswehack-claude.png" width="104"/>
<span class="reading-copy">
<span class="reading-source">YesWeHack</span>
<span class="reading-title">Claude Code for bug bounty</span>
<span class="reading-note">Setup and worked lab examples.</span>
</span>
</a>
</li>
<li>
<a class="reading-link" href="https://www.yeswehack.com/learn-bug-bounty/llm-series-codex" rel="noopener" target="_blank">
<img alt="" height="55" loading="lazy" src="/assets/hackbot-blog/reading/yeswehack-codex.png" width="104"/>
<span class="reading-copy">
<span class="reading-source">YesWeHack</span>
<span class="reading-title">Codex for bug bounty</span>
<span class="reading-note">Using Codex during a research task.</span>
</span>
</a>
</li>
<li>
<a class="reading-link" href="https://www.anthropic.com/research/effective-context-engineering-for-ai-agents" rel="noopener" target="_blank">
<img alt="" height="55" loading="lazy" src="/assets/hackbot-blog/reading/anthropic-context.jpg" width="104"/>
<span class="reading-copy">
<span class="reading-source">Anthropic</span>
<span class="reading-title">Context engineering for agents</span>
<span class="reading-note">What to keep, retrieve and summarize.</span>
</span>
</a>
</li>
<li>
<a class="reading-link" href="https://www.anthropic.com/research/multi-agent-research-system" rel="noopener" target="_blank">
<img alt="" height="55" loading="lazy" src="/assets/hackbot-blog/reading/anthropic-research.jpg" width="104"/>
<span class="reading-copy">
<span class="reading-source">Anthropic</span>
<span class="reading-title">Building a multi-agent research system</span>
<span class="reading-note">Coordinator and worker design choices.</span>
</span>
</a>
</li>
<li>
<a class="reading-link" href="https://arcanum-sec.com/blog/hackbots/" rel="noopener" target="_blank">
<img alt="" height="55" loading="lazy" src="/assets/hackbot-blog/reading/arcanum-hackbots.png" width="104"/>
<span class="reading-copy">
<span class="reading-source">Jason Haddix · Arcanum</span>
<span class="reading-title">Building AI Hackbots, Part 1</span>
<span class="reading-note">Lessons from building his own setup.</span>
</span>
</a>
</li>
<li>
<a class="reading-link" href="https://brutecat.com/articles/hacking-google-with-ai/#enter-a-i" rel="noopener" target="_blank">
<img alt="" height="55" loading="lazy" src="/assets/hackbot-blog/reading/brutecat-google.png" width="104"/>
<span class="reading-copy">
<span class="reading-source">BruteCat</span>
<span class="reading-title">Hacking Google with A.I.</span>
<span class="reading-note">A researcher’s account of using AI.</span>
</span>
</a>
</li>
<li>
<a class="reading-link" href="https://arxiv.org/abs/2508.20816" rel="noopener" target="_blank">
<img alt="" height="55" loading="lazy" src="/assets/hackbot-blog/reading/mapta-paper.png" width="104"/>
<span class="reading-copy">
<span class="reading-source">David &amp; Gervais · arXiv</span>
<span class="reading-title">MAPTA: multi-agent web testing</span>
<span class="reading-note">A multi-agent system and its evaluation.</span>
</span>
</a>
</li>
<li>
<a class="reading-link" href="https://portswigger.net/research/can-ai-do-novel-security-research" rel="noopener" target="_blank">
<img alt="" height="55" loading="lazy" src="/assets/hackbot-blog/reading/kettle-terminator.png" width="104"/>
<span class="reading-copy">
<span class="reading-source">James Kettle · PortSwigger</span>
<span class="reading-title">Can AI do novel security research?</span>
<span class="reading-note">HTTP Terminator and moving checks into code.</span>
</span>
</a>
</li>
</ul>

### Talks

<ul class="reading-list">
  <li>
    <a class="reading-link" href="https://www.youtube.com/watch?v=cRKToFkZMvk" target="_blank" rel="noopener">
      <img src="/assets/hackbot-blog/reading/haddix-masterclass.jpg" alt="" width="104" height="55" loading="lazy">
      <span class="reading-copy">
        <span class="reading-source">Jason Haddix · DEF CON 34 BBV</span>
        <span class="reading-title">Hackbots masterclass</span>
        <span class="reading-note">A longer session on building hackbots.</span>
      </span>
    </a>
  </li>
  <li>
    <a class="reading-link" href="https://www.youtube.com/watch?v=GDm_uH6VxPY" target="_blank" rel="noopener">
      <img src="/assets/hackbot-blog/reading/google-agent-patterns.jpg" alt="" width="104" height="55" loading="lazy">
      <span class="reading-copy">
        <span class="reading-source">Google Cloud Tech</span>
        <span class="reading-title">AI agent design patterns</span>
        <span class="reading-note">Patterns for organizing agent workflows.</span>
      </span>
    </a>
  </li>
</ul>
