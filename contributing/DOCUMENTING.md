# Documentation Standards

## Philosophy

**Documentation is product.** Code changes without corresponding doc updates are incomplete.

- Every new CLI command, flag, or behavior change should be reflected in docs
- Think about docs from the start, not as an afterthought
- If a user would need to know about it, document it

## Overview

Documentation is built with [Docusaurus](https://docusaurus.io/) and deployed automatically via GitHub Actions.

- **Source**: `docs/docs/` (Markdown files)
- **Config**: `docs/docusaurus.config.js`
- **Sidebar**: `docs/sidebars.js`

## Development

```bash
cd docs

# Install dependencies (first time only)
npm install

# Start dev server (hot reload)
npm run dev

# Build for production
npm run build

# Preview production build
npm run serve
```

## Guidelines

### When to Update Docs

- **New CLI commands**: Add to `reference/cli/`
- **New features**: Add guide to `guides/`
- **Config changes**: Update `reference/configuration.md`
- **Security changes**: Update `security/` section

### Writing Style

- Use imperative mood for titles ("Configure TLS" not "Configuring TLS")
- Include working code examples
- Keep CLI examples consistent with actual command output
- Document flags and environment variables

### Sidebar Updates

When adding new pages, update `docs/sidebars.js` to include them in navigation.
