import Account from '../account/Account';

export default interface IAccountSource {
  getAccounts(id: string): Promise<Account[]>;
  authenticate(login: string, password: string): Promise<Account | undefined>;
  matchClaims(claims: Record<string, string>): Promise<Account | undefined>;
}
