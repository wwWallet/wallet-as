import fs from "fs";
import path from "path";
import Account from "../account/Account";
import IAccountSource from "../interfaces/IAccountSource";

type AccountRecord = {
  id: string;
  family_name?: string;
  given_name?: string;
  birthdate?: string;
  email?: string;
  [key: string]: unknown;
};

type AccountsFile = {
  accounts: AccountRecord[];
};

const normalize = (value: string | undefined) =>
  (value ?? "").trim().toLowerCase();

const resolveAccountsFile = (): string =>
  path.join(process.cwd(), "dataset/accounts.json");

export class FileAccountSource implements IAccountSource {
  private accounts: Account[] = [];
  private records: AccountRecord[] = [];

  constructor(filePath?: string) {
    const resolvedPath = filePath ?? resolveAccountsFile();
    const raw = fs.readFileSync(resolvedPath, "utf-8");
    const parsed = JSON.parse(raw) as AccountsFile;
    this.records = parsed.accounts || [];
    this.accounts = this.records.map((record) => new Account(record.id, record));
  }

  public async getAccounts(id: string) {
    if (!id) {
      return Promise.resolve(this.accounts);
    }
    return Promise.resolve(this.accounts.filter((ac) => ac.sub === id));
  }

  public async authenticate(_login: string, _password: string) {
    return Promise.resolve(undefined);
  }

  public async matchClaims(claims: Record<string, string>) {
    const normalizedClaims = Object.fromEntries(
      Object.entries(claims).map(([key, value]) => [key, normalize(value)])
    );
    const claimEntries = Object.entries(normalizedClaims);
    if (claimEntries.length === 0) {
      return Promise.resolve(undefined);
    }

    const record = this.records.find((acc) =>
      claimEntries.every(([key, value]) => normalize(String(acc[key] ?? "")) === value)
    );

    if (!record) {
      return Promise.resolve(undefined);
    }
    return Promise.resolve(new Account(record.id, record));
  }
}
