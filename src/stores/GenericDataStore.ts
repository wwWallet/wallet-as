import Valkey from "iovalkey";
import { GenericStore } from "wallet-common";

export class GenericDataStore<TKey, TValue> implements GenericStore<TKey, TValue> {
	private readonly indexKey: string;

	constructor(
		private readonly client: Valkey,
		private readonly prefix: string,
		private readonly serializeKey: (key: TKey) => string = JSON.stringify,
		private readonly serializeValue: (value: TValue) => string = JSON.stringify,
		private readonly deserializeValue: (value: string) => TValue = JSON.parse,
	) {
		this.indexKey = `${prefix}:__keys`;
	}

	private buildKey(key: TKey): string {
		return `${this.prefix}:${this.serializeKey(key)}`;
	}

	async get(key: TKey): Promise<TValue | undefined> {
		const value = await this.client.get(this.buildKey(key));

		if (value === null) {
			return undefined;
		}

		return this.deserializeValue(value);
	}

	async set(key: TKey, value: TValue, ttlMs?: number): Promise<void> {
		const redisKey = this.buildKey(key);
		const serializedValue = this.serializeValue(value);
		if(ttlMs !== undefined) {
			await this.client
				.multi()
				.set(redisKey, serializedValue, "PX", ttlMs)
				.sadd(this.indexKey, redisKey)
				.exec();
		} else {
			await this.client
				.multi()
				.set(redisKey, serializedValue)
				.sadd(this.indexKey, redisKey)
				.exec();
		}
	}

	async delete(key: TKey): Promise<void> {
		const redisKey = this.buildKey(key);

		await this.client
			.multi()
			.del(redisKey)
			.srem(this.indexKey, redisKey)
			.exec();
	}

	async getAll(): Promise<TValue[]> {
		const keys = await this.client.smembers(this.indexKey);

		if (keys.length === 0) {
			return [];
		}

		const values = await this.client.mget(...keys);

		return values
			.filter((v): v is string => v !== null)
			.map(v => this.deserializeValue(v));
	}
}