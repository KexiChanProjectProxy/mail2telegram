import type { EmailMessage } from '@cloudflare/workers-types';
import type { Environment } from '../types';
import { Dao, loadArrayFromRaw } from '../db';
import { logger } from '../logger';

export type AddressCheckStatus = 'white' | 'block' | 'no_match';

function testAddress(address: string, pattern: string): boolean {
    if (pattern.toLowerCase() === address.toLowerCase()) {
        return true;
    }
    try {
        const regex = new RegExp(pattern, 'i');
        return regex.test(address);
    } catch {
        return false;
    }
}

export async function checkAddressStatus(addresses: string[], env: Environment): Promise<{ [key: string]: AddressCheckStatus }> {
    const matchAddress = (list: string[], address: string): boolean => {
        for (const item of list) {
            if (!item) {
                continue;
            }
            if (testAddress(address, item)) {
                return true;
            }
        }
        return false;
    };
    const {
        BLOCK_LIST,
        WHITE_LIST,
        DISABLE_LOAD_REGEX_FROM_DB,
        DB,
    } = env;
    const blockList = loadArrayFromRaw(BLOCK_LIST);
    const whiteList = loadArrayFromRaw(WHITE_LIST);
    const dao = new Dao(DB);
    if (!(DISABLE_LOAD_REGEX_FROM_DB === 'true')) {
        blockList.push(...(await dao.loadArrayFromDB('BLOCK_LIST')));
        whiteList.push(...(await dao.loadArrayFromDB('WHITE_LIST')));
    }
    const result: { [key: string]: AddressCheckStatus } = {};

    for (const addr of addresses) {
        if (!addr) {
            continue;
        }
        if (matchAddress(whiteList, addr)) {
            logger.info('Address matched whitelist', { address: addr });
            result[addr] = 'white';
            continue;
        }
        if (matchAddress(blockList, addr)) {
            logger.info('Address matched blocklist', { address: addr });
            result[addr] = 'block';
            continue;
        }
        result[addr] = 'no_match';
    }
    return result;
}

export async function isMessageBlock(message: EmailMessage, env: Environment): Promise<boolean> {
    const addresses = [
        message.from,
        message.to,
    ];
    const res = await checkAddressStatus(addresses, env);
    for (const key in res) {
        switch (res[key]) {
            case 'white':
                logger.info('Message allowed by whitelist', { address: key });
                return false;
            case 'block':
                logger.info('Message blocked by blocklist', { address: key });
                return true;
            default:
                break;
        }
    }
    return false;
}
