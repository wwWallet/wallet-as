export default class Account {
  public sub: string;
  private _claims: any;

  constructor(id: string, claims: object) {
    this.sub = id;
    this._claims = claims;
  }

  public claims() {
    return this._claims;
  }
}
