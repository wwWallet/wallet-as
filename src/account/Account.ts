export default class Account {
  public sub: string;
  private _claims: Record<string, unknown>;

  constructor(id: string, claims: Record<string, unknown>) {
    this.sub = id;
    this._claims = claims;
  }

  public claims() {
    return this._claims;
  }
}
