import { activeConfiguration } from './configuration.js';
import { loadConfig } from './config.js';
import { OneIdClient } from './auth/oneid-client.js';
import { LightRagClient } from './lightrag-client.js';

/** Each request captures one client; activation never mutates an in-flight client. */
export class ReloadingKnowledgeClient {
  constructor(config) {
    this.config = config;
    this.client = new LightRagClient(config, new OneIdClient(config));
    this.selection = Promise.resolve();
  }

  async select() {
    const pending = this.selection.then(async () => {
      const active = await activeConfiguration(this.config.configPath);
      if (active.revision !== this.config.configurationRevision) {
        const config = await loadConfig(this.config.configPath, { allowMissingCredentials: true });
        this.client = new LightRagClient(config, new OneIdClient(config));
        this.config = config;
      }
      return this.client;
    });
    this.selection = pending.then(() => {}, () => {});
    return pending;
  }

  async query(input, options) { return (await this.select()).query(input, options); }
  async status(options) { return (await this.select()).status(options); }
  async list(input, options) { return (await this.select()).list(input, options); }
}
