import type { IRequest, RouterType } from 'itty-router';
import type { AddressListStoreKey } from '../../db';
import type { Environment } from '../../types';
import { validate } from '@telegram-apps/init-data-node/web';
import { json, Router } from 'itty-router';
import { Dao } from '../../db';
import { createTelegramBotAPI, telegramCommands, telegramWebhookHandler, tmaHTML } from '../../telegram';
import { logger } from '../../logger';

class HTTPError extends Error {
    readonly status: number;
    constructor(status: number, message: string) {
        super(message);
        this.status = status;
    }
}

function createTmaAuthMiddleware(env: Environment): (req: Request) => Promise<void> {
    const {
        TELEGRAM_TOKEN,
        TELEGRAM_ID,
    } = env;
    return async (req: Request): Promise<void> => {
        const [authType, authData = ''] = (req.headers.get('Authorization') || '').split(' ');
        if (authType !== 'tma') {
            throw new HTTPError(401, 'Invalid authorization type');
        }
        try {
            await validate(authData, TELEGRAM_TOKEN, {
                expiresIn: 3600,
            });
            const user = JSON.parse(new URLSearchParams(authData).get('user') || '{}');
            for (const id of TELEGRAM_ID.split(',')) {
                if (id === `${user.id}`) {
                    return;
                }
            }
            throw new HTTPError(403, 'Permission denied');
        } catch (e) {
            throw new HTTPError(401, (e as Error).message);
        }
    };
}

type AddressType = 'block' | 'white';

function addressParamsCheck(address: string, type: AddressType): AddressListStoreKey {
    const keyMap: { [key in AddressType]: AddressListStoreKey } = {
        block: 'BLOCK_LIST',
        white: 'WHITE_LIST',
    };
    if (!address || !type) {
        throw new HTTPError(400, 'Missing address or type');
    }
    if (keyMap[type] === undefined) {
        throw new HTTPError(400, 'Invalid type');
    }
    return keyMap[type];
}

function errorHandler(error: Error): Response {
    logger.error('HTTP error', { status: error instanceof HTTPError ? error.status : 500, message: error.message });
    if (error instanceof HTTPError) {
        return new Response(JSON.stringify({
            error: error.message,
        }), { status: error.status });
    }
    return new Response(JSON.stringify({
        error: error.message,
    }), { status: 500 });
}

function createRouter(env: Environment): RouterType {
    const router = Router({
        catch: errorHandler,
        finally: [json],
    });

    const {
        TELEGRAM_TOKEN,
        DOMAIN,
        DB,
    } = env;
    const dao = new Dao(DB);
    const auth = createTmaAuthMiddleware(env);

    router.get('/', async (): Promise<Response> => {
        return new Response(null, {
            status: 302,
            headers: {
                location: 'https://github.com/TBXark/mail2telegram',
            },
        });
    });

    router.get('/init', async (): Promise<any> => {
        if (!DOMAIN) {
            throw new HTTPError(500, 'DOMAIN environment variable is not set');
        }
        logger.info('Init endpoint called');
        const api = createTelegramBotAPI(TELEGRAM_TOKEN);
        const webhook = await api.setWebhook({
            url: `https://${DOMAIN}/telegram/${TELEGRAM_TOKEN}/webhook`,
        });
        const commands = await api.setMyCommands({
            commands: telegramCommands,
        });
        return {
            webhook: await webhook.json(),
            commands: await commands.json(),
        };
    });

    /// Telegram Mini Apps

    router.get('/tma', async (): Promise<Response> => {
        return new Response(tmaHTML, {
            headers: {
                'content-type': 'text/html; charset=utf-8',
            },
        });
    });

    router.post('/api/address/add', auth, async (req: IRequest): Promise<any> => {
        const { address, type } = await req.json() as { address: string; type: AddressType };
        const key = addressParamsCheck(address, type);
        await dao.addAddress(address, key);
        return { success: true };
    });

    router.post('/api/address/remove', auth, async (req: IRequest): Promise<any> => {
        const { address, type } = await req.json() as { address: string; type: AddressType };
        const key = addressParamsCheck(address, type);
        await dao.removeAddress(address, key);
        return { success: true };
    });

    router.get('/api/address/list', auth, async (): Promise<any> => {
        const block = await dao.loadArrayFromDB('BLOCK_LIST');
        const white = await dao.loadArrayFromDB('WHITE_LIST');
        return { block, white };
    });

    /// Webhook

    router.post('/telegram/:token/webhook', async (req: IRequest): Promise<any> => {
        logger.info('Telegram webhook received', { tokenPrefix: req.params.token?.slice(0, 8) });
        if (req.params.token !== TELEGRAM_TOKEN) {
            logger.warn('Invalid telegram token in webhook', { expected: TELEGRAM_TOKEN?.slice(0, 8) });
            throw new HTTPError(403, 'Invalid token');
        }
        try {
            await telegramWebhookHandler(req, env);
        } catch (e) {
            logger.error('Telegram webhook handler error', { error: (e as Error).message });
        }
        return { success: true };
    });

    /// Preview

    router.get('/email/:id', async (req: IRequest): Promise<Response> => {
        const id = req.params.id;
        const mode = req.query.mode || 'text';
        const value = await dao.loadMailCache(id);
        let text = value?.text || '';
        let contentType = 'text/plain; charset=utf-8';
        if (mode === 'html') {
            text = value?.html || '';
            contentType = 'text/html; charset=utf-8';
        }
        return new Response(text, {
            headers: { 'content-type': contentType },
        });
    });

    router.all('*', async () => {
        throw new HTTPError(404, 'Not found');
    });

    return router;
}

export async function fetchHandler(request: Request, env: Environment): Promise<Response> {
    logger.info('Incoming request', { method: request.method, path: new URL(request.url).pathname });
    const router = createRouter(env);
    return router.fetch(request).catch((e) => {
        logger.error('Unhandled error in fetch handler', { error: e.message });
        return new Response(JSON.stringify({
            error: e.message,
        }), { status: 500 });
    });
}
