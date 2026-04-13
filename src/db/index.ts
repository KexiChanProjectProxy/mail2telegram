import type { KVNamespace } from '@cloudflare/workers-types';
import type { EmailCache, EmailHandleStatus } from '../types';
import { logger } from '../logger';

export type AddressListStoreKey = 'BLOCK_LIST' | 'WHITE_LIST';

export class Dao {
    private readonly db: KVNamespace;

    constructor(db: KVNamespace) {
        this.db = db;
        this.loadArrayFromDB = this.loadArrayFromDB.bind(this);
        this.addAddress = this.addAddress.bind(this);
        this.removeAddress = this.removeAddress.bind(this);
        this.loadMailStatus = this.loadMailStatus.bind(this);
        this.loadMailCache = this.loadMailCache.bind(this);
    }

    async loadArrayFromDB(key: AddressListStoreKey): Promise<string[]> {
        try {
            const raw = await this.db.get(key);
            return loadArrayFromRaw(raw);
        } catch (e) {
            logger.error('KV load failed', { key, operation: 'loadArrayFromDB', error: (e as Error).message });
        }
        return [];
    }

    async addAddress(address: string, type: AddressListStoreKey): Promise<void> {
        logger.debug('KV write', { key: type, operation: 'addAddress' });
        const list = await this.loadArrayFromDB(type);
        list.unshift(address);
        await this.db.put(type, JSON.stringify(list));
    }

    async removeAddress(address: string, type: AddressListStoreKey): Promise<void> {
        logger.debug('KV write', { key: type, operation: 'removeAddress' });
        const list = await this.loadArrayFromDB(type);
        const result = list.filter(item => item !== address);
        await this.db.put(type, JSON.stringify(result));
    }

    async loadMailStatus(id: string, guardian: boolean): Promise<EmailHandleStatus> {
        const defaultStatus = {
            telegram: false,
            forward: [],
            webhook: [],
        };
        if (guardian) {
            try {
                const raw = await this.db.get(id);
                if (raw) {
                    logger.debug('KV load', { key: id, operation: 'loadMailStatus', found: true });
                    return {
                        ...defaultStatus,
                        ...JSON.parse(raw),
                    };
                }
            } catch (e) {
                logger.error('KV load failed', { key: id, operation: 'loadMailStatus', error: (e as Error).message });
            }
        }
        logger.debug('KV load', { key: id, operation: 'loadMailStatus', found: false });
        return defaultStatus;
    }

    async saveMailStatus(id: string, status: EmailHandleStatus, ttl?: number): Promise<void> {
        logger.debug('KV write', { key: id, operation: 'saveMailStatus', ttl });
        await this.db.put(id, JSON.stringify(status), { expirationTtl: ttl });
    }

    async loadMailCache(id: string): Promise<EmailCache | null> {
        try {
            const raw = await this.db.get(id);
            if (raw) {
                logger.debug('KV load', { key: id, operation: 'loadMailCache', found: true });
                return JSON.parse(raw);
            }
        } catch (e) {
            logger.error('KV load failed', { key: id, operation: 'loadMailCache', error: (e as Error).message });
        }
        logger.debug('KV load', { key: id, operation: 'loadMailCache', found: false });
        return null;
    }

    async saveMailCache(id: string, cache: EmailCache, ttl?: number): Promise<void> {
        logger.debug('KV write', { key: id, operation: 'saveMailCache', ttl });
        await this.db.put(id, JSON.stringify(cache), { expirationTtl: ttl });
    }

    async telegramIDToMailID(id: string): Promise<string | null> {
        return await this.db.get(`TelegramID2MailID:${id}`);
    }

    async saveTelegramIDToMailID(id: string, mailID: string, ttl?: number): Promise<void> {
        logger.debug('KV write', { key: `TelegramID2MailID:${id}`, operation: 'saveTelegramIDToMailID', ttl });
        await this.db.put(`TelegramID2MailID:${id}`, mailID, { expirationTtl: ttl });
    }
}

export function loadArrayFromRaw(raw: string | null): string[] {
    if (!raw) {
        return [];
    }
    let list = [];
    try {
        list = JSON.parse(raw);
    } catch {
        return [];
    }
    if (!Array.isArray(list)) {
        return [];
    }
    return list;
}
