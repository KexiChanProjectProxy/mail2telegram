import type { Environment } from './types';
import type { ExecutionContext } from '@cloudflare/workers-types';
import { fetchHandler } from './handler/fetch';
import { emailHandler } from './handler/mail';
import { initLogger } from './logger';
import './polyfill';

export default {
    fetch: (request: Request, env: Environment, _ctx: ExecutionContext): Promise<Response> => {
        initLogger(env.DEBUG);
        return fetchHandler(request, env);
    },
    email: emailHandler,
};
