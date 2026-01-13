import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://faiscadev.github.io',
  base: '/zopp',
  integrations: [
    starlight({
      title: 'zopp',
      description: 'Zero-knowledge secrets manager. Own your secrets. Stay secure.',
      logo: {
        dark: './src/assets/logo-dark.svg',
        light: './src/assets/logo-light.svg',
        replacesTitle: true,
      },
      social: {
        github: 'https://github.com/faiscadev/zopp',
      },
      editLink: {
        baseUrl: 'https://github.com/faiscadev/zopp/edit/main/docs/',
      },
      customCss: ['./src/styles/custom.css'],
      head: [
        {
          tag: 'meta',
          attrs: {
            property: 'og:image',
            content: 'https://faiscadev.github.io/zopp/og-image.png',
          },
        },
      ],
      sidebar: [
        {
          label: 'Start Here',
          items: [
            { label: 'Introduction', slug: 'index' },
            { label: 'Quickstart', slug: 'quickstart' },
          ],
        },
        {
          label: 'Installation',
          items: [
            { label: 'Overview', slug: 'installation' },
            { label: 'CLI', slug: 'installation/cli' },
            { label: 'Docker', slug: 'installation/docker' },
            { label: 'Kubernetes', slug: 'installation/kubernetes' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Overview', slug: 'guides' },
            { label: 'Core Concepts', slug: 'guides/core-concepts' },
            { label: 'Team Collaboration', slug: 'guides/team-collaboration' },
            { label: 'Kubernetes Operator', slug: 'guides/kubernetes-operator' },
            { label: 'CI/CD Integration', slug: 'guides/ci-cd' },
            { label: 'Import & Export', slug: 'guides/import-export' },
          ],
        },
        {
          label: 'CLI Reference',
          items: [
            { label: 'Overview', slug: 'reference/cli' },
            { label: 'join', slug: 'reference/cli/join' },
            { label: 'workspace', slug: 'reference/cli/workspace' },
            { label: 'project', slug: 'reference/cli/project' },
            { label: 'environment', slug: 'reference/cli/environment' },
            { label: 'secret', slug: 'reference/cli/secret' },
            { label: 'principal', slug: 'reference/cli/principal' },
            { label: 'permission', slug: 'reference/cli/permission' },
            { label: 'group', slug: 'reference/cli/group' },
            { label: 'invite', slug: 'reference/cli/invite' },
            { label: 'sync', slug: 'reference/cli/sync' },
            { label: 'diff', slug: 'reference/cli/diff' },
            { label: 'audit', slug: 'reference/cli/audit' },
            { label: 'run', slug: 'reference/cli/run' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Configuration', slug: 'reference/configuration' },
            { label: 'Environment Variables', slug: 'reference/environment-variables' },
          ],
        },
        {
          label: 'Self-Hosting',
          items: [
            { label: 'Overview', slug: 'self-hosting' },
            { label: 'Server Deployment', slug: 'self-hosting/server' },
            { label: 'Database Setup', slug: 'self-hosting/database' },
            { label: 'TLS Configuration', slug: 'self-hosting/tls' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'Overview', slug: 'security' },
            { label: 'Architecture', slug: 'security/architecture' },
            { label: 'Cryptography', slug: 'security/cryptography' },
          ],
        },
      ],
    }),
  ],
});
