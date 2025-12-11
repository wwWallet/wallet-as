import IAccountSource from '../interfaces/IAccountSource';
import Account from "../account/Account";

export class DemoAccountSource implements IAccountSource {
  private accounts = [
    new Account("test", {}),
    new Account("test2", {}),
  ]

  public async getAccounts() {
    return Promise.resolve(this.accounts);
  }

  public async authenticate(login: string, password: string) {
    return Promise.resolve(
      this.accounts.find(ac => ac.sub === login)
    )
  }
}
