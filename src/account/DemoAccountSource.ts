import IAccountSource from '../interfaces/IAccountSource';
import Account from "../account/Account";
import config from '../config';

export class DemoAccountSource implements IAccountSource {
  private accounts: Account[] = []

  constructor() {
    if (config.demoUsername) {
      this.accounts.push(new Account(config.demoUsername, {}));
    }
  }

  public async getAccounts() {
    return Promise.resolve(this.accounts);
  }

  public async authenticate(login: string, password: string) {
    return Promise.resolve(
      this.accounts.find(ac => ac.sub === login)
    )
  }
}
