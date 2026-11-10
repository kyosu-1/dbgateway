import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";
import path from "node:path";

const repo = "https://github.com/kyosu-1/dbgateway";

// Links from a doc to files outside docs/ (examples, Terraform, LICENSE...)
// point to the repository on GitHub.
function repoLinks(md: any) {
  const render = md.renderer.rules.link_open ?? ((t: any, i: number, o: any, e: any, s: any) => s.renderToken(t, i, o));
  md.renderer.rules.link_open = (tokens: any, idx: number, options: any, env: any, self: any) => {
    const href: string | null = tokens[idx].attrGet("href");
    if (href && !/^[a-z]+:|^#|^\//i.test(href) && env?.relativePath) {
      const [target, hash] = href.split("#");
      const resolved = path.posix.normalize(path.posix.join("docs", path.posix.dirname(env.relativePath), target));
      if (!resolved.startsWith("docs/")) {
        const kind = target.endsWith("/") || !path.posix.extname(target) ? "tree" : "blob";
        tokens[idx].attrSet("href", `${repo}/${kind}/main/${resolved}${hash ? "#" + hash : ""}`);
      }
    }
    return render(tokens, idx, options, env, self);
  };
}

export default withMermaid(defineConfig({
  title: "dbgateway",
  description: "An SQL-aware gateway that lets AI agents and people use production databases safely.",
  base: "/dbgateway/",
  lang: "en-US",
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ["README.md"],
  head: [["link", { rel: "icon", type: "image/svg+xml", href: "/dbgateway/logo.svg" }]],
  markdown: { config: repoLinks },
  vite: { build: { chunkSizeWarningLimit: 4096 } }, // mermaid is large
  themeConfig: {
    logo: "/logo.svg",
    nav: [
      { text: "Guide", link: "/introduction" },
      { text: "Reference", link: "/configuration" },
      { text: "GitHub", link: repo },
    ],
    sidebar: [
      {
        text: "Getting started",
        items: [
          { text: "What is dbgateway?", link: "/introduction" },
          { text: "Quickstart", link: "/quickstart" },
          { text: "Architecture", link: "/architecture" },
        ],
      },
      {
        text: "Using dbgateway",
        items: [
          { text: "Connect AI agents (MCP)", link: "/mcp" },
          { text: "SQL editor", link: "/console" },
          { text: "CLI", link: "/cli" },
          { text: "Migration lint", link: "/lint" },
          { text: "Approvals", link: "/approvals" },
          { text: "Notifications", link: "/notifications" },
        ],
      },
      {
        text: "Administration",
        items: [
          { text: "Policies and roles", link: "/policies" },
          { text: "Quotas", link: "/quotas" },
          { text: "Masking and audit", link: "/masking-and-audit" },
          { text: "Authentication", link: "/authentication" },
          { text: "SCIM", link: "/scim" },
          { text: "MySQL", link: "/mysql" },
        ],
      },
      {
        text: "Deployment",
        items: [
          { text: "Deploying dbgateway", link: "/deploy" },
          { text: "Kubernetes (Helm)", link: "/kubernetes" },
          { text: "Operations", link: "/operations" },
          { text: "High availability", link: "/ha" },
        ],
      },
      {
        text: "Reference",
        items: [
          { text: "Configuration", link: "/configuration" },
          { text: "Security model", link: "/security" },
          { text: "Design decisions", link: "/design-decisions" },
        ],
      },
    ],
    search: { provider: "local" },
    socialLinks: [{ icon: "github", link: repo }],
    editLink: { pattern: `${repo}/edit/main/docs/:path`, text: "Edit this page on GitHub" },
    footer: { message: "Released under the Apache License 2.0." },
    outline: { level: [2, 3] },
  },
}));
