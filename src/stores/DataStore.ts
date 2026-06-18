import Valkey from "iovalkey";
import { GenericStore } from "wallet-common";

export class DataStore<TValue> implements GenericStore<string, TValue> {
	constructor(
		private readonly client: Valkey,
		private readonly prefix: string,
		private readonly serializeValue: (value: TValue) => string = JSON.stringify,
		private readonly deserializeValue: (value: string) => TValue = JSON.parse,
	) {
		this.client = client;
	}

	private buildKey(key: string): string {
		return `${this.prefix}:${key}`;
	}

	async get(key: string): Promise<TValue | undefined> {
		const value = await this.client.get(this.buildKey(key));

		return value !== null ? this.deserializeValue(value) : undefined;
	}

	async set(key: string, value: TValue, ttlMs?: number): Promise<void> {
		const builtKey = this.buildKey(key);
		const serializedValue = this.serializeValue(value);

		if(ttlMs !== undefined) {
			await this.client.set(
				builtKey,
				serializedValue,
				"PX",
				ttlMs
			);
		} else {
			await this.client.set(
				builtKey,
				serializedValue
			);
		}
	}

	async delete(key: string): Promise<void> {
		await this.client.del(this.buildKey(key));
	}

	async getAll(): Promise<TValue[]> {
		throw new Error(
			"getAll() is not supported by DataStore.",
		);
	}
}