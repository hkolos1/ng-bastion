---
title: Browser agent tools (WebMCP)
description: Discover the security rule catalog, inspect a TypeScript snippet locally and render an HTML report with the experimental Angular WebMCP integration.
---

## Using a browser agent

Open NgBastion in a browser with a compatible agent and use its tool discovery interface. Ask it to list NgBastion tools, explain NGB018, then analyze a small TypeScript file. Discovery depends on the browser, agent and their settings. Angular registers six page tools for the lifetime of the client application. A browser exposing the API does not establish an agent connection. Ordinary browsing and the [playground](/playground/) work independently.

WebMCP is experimental. These tools belong to the open page. A standalone MCP server would require a separate process and transport. NgBastion hosts no model or agent service. See the [Angular integration guide](https://angular.dev/ai/webmcp) and [browser tool guide](https://developer.chrome.com/docs/modern-web-guidance/guides/webmcp/agentic-javascript-tools).

## Tool requests and responses

| Tool | Example arguments | Response |
| --- | --- | --- |
| ngbastion_get_rules | `{"category":"angular-xss","limit":5,"offset":0}` | Total matching rules, offset and rule summaries in ID order |
| ngbastion_explain_rule | `{"ruleId":"NGB018"}` | Rule metadata, detection boundaries, examples, remediation and documentation. A null autofix means no documented automatic fix |
| ngbastion_search_rules | `{"query":"frontend secrets","severity":"high"}` | Ranked matches and total before the result limit |
| ngbastion_analyze_snippet | `{"code":"export const title = 'Shop';","filename":"shop.ts"}` | Status, executed and skipped IDs, limitations and, on success, findings, duration and an analysis ID |
| ngbastion_generate_report | `{"analysisId":"<ID returned by analysis>"}` | Filename, MIME type and standalone HTML that can be saved to a file |
| ngbastion_get_installation | `{}` | npm package, Node requirements, install, configuration and scan commands |

For example the snippet above returns status `ok`, zero findings and `rulesExecuted: ["NGB018"]`. Compare that with `{"code":"const a = 1;","ruleIds":["NGB001"]}`, which returns `unsupported`. Catalog and search pages default to 10 results and accept limits up to 25.

## Coverage and privacy

The live analyzer checks TypeScript string literals using the source pass of the CLI's NGB018 hardcoded frontend secrets rule. It parses one .ts file in a dedicated worker. It does not check JSON configuration, templates, dependencies, types across files, policy exceptions or other project rules. Use the [CLI](/docs/getting-started/first-scan/) for project analysis. The separate fixture walkthrough shows precomputed project findings.

Source stays in the browser during analysis. Only NgBastion application assets are loaded. Submitted code is never run. The agent that supplies the code and reads results has its own privacy settings. The page retains up to four recent successful results in memory for reports. Refreshing the page clears them. Reports omit source excerpts from secret findings.

## Troubleshooting

If tools are missing, check the agent's experimental WebMCP support and reload the page. If the worker reports a syntax or resource error, reduce the input to a valid TypeScript example under 32,768 characters and 50 findings. A worker has 10 seconds including startup. For an expired report ID, analyze the snippet again. The playground can download the same report directly.

## Verification

The browser integration test discovers and invokes all six tools in Chrome using Playwright and the experimental `--enable-features=WebMCP` flag. It also exercises the playground and downloads a report with the browser API unavailable. From the repository root, run `pnpm build`, then `node tests/browser/playground.mjs` with Google Chrome installed. The test uses a local static server and requires no agent account.

To check an agent manually, open the site, ask it to call `ngbastion_get_rules` with a limit of one, and check that the response includes NGB001 and a total of 100. Ask it to analyze the TypeScript example above and pass the returned analysis ID to `ngbastion_generate_report` in the same tab.
