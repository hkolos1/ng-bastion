import cli from '../../generated/cli.json';
import { parameters } from './validation';

export function getInstallation(input: unknown) {
  parameters(input, []);
  return {
    status: 'ok',
    package: cli.name,
    node: cli.node,
    install: 'npm install --save-dev ' + cli.name,
    configure: 'npx ngbastion init --preset recommended',
    examples: ['npx ngbastion doctor', 'npx ngbastion scan'],
    documentation: ['/docs/getting-started/installation/', '/docs/configuration/', '/docs/cli-reference/'],
  };
}
