import { VERSION } from './version.js';

export const HELP = `NgBastion ${VERSION} — Angular-aware, local-first security scanner

Usage: ngbastion <command> [options]

Commands:
  scan [dir]      Analyze an Angular workspace
  init            Create an NgBastion configuration file
  explain <rule>  Show detailed documentation for a rule
  rules           List available security rules
  doctor          Check the environment and configuration

Run 'ngbastion <command> --help' for command options.`;

export async function run(argv: string[]): Promise<number> {
  const [command] = argv;
  if (!command || command === '--help' || command === '-h' || command === 'help') {
    console.log(HELP);
    return 0;
  }
  if (command === '--version' || command === '-v') {
    console.log(VERSION);
    return 0;
  }
  console.error(`ngbastion: command '${command}' is not implemented yet`);
  return 2;
}
