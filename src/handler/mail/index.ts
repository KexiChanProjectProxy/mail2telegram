import type { ForwardableEmailMessage } from '@cloudflare/workers-types';
import type { BlockPolicy, EmailCache, Environment } from '../../types';
import { Dao } from '../../db';
import { isMessageBlock, parseEmail, renderEmailListMode } from '../../mail';
import { createTelegramBotAPI } from '../../telegram';
import { sendMailToWebhooks } from '../../webhook';
import { logger } from '../../logger';

export async function sendMailToTelegram(mail: EmailCache, env: Environment): Promise<number[]> {
    const {
        TELEGRAM_TOKEN,
        TELEGRAM_ID,
    } = env;
    const req = await renderEmailListMode(mail, env);
    const api = createTelegramBotAPI(TELEGRAM_TOKEN);
    const messageID: number[] = [];
    for (const id of TELEGRAM_ID.split(',')) {
        const msg = await api.sendMessageWithReturns({
            chat_id: id,
            ...req,
        });
        messageID.push(msg.result.message_id);
    }
    return messageID;
}

export async function emailHandler(message: ForwardableEmailMessage, env: Environment): Promise<void> {
    const {
        FORWARD_LIST,
        WEBHOOK_LIST,
        BLOCK_POLICY,
        GUARDIAN_MODE,
        DB,
        MAIL_TTL,
        MAX_EMAIL_SIZE,
        MAX_EMAIL_SIZE_POLICY,
    } = env;

    const dao = new Dao(DB);
    const id = message.headers.get('Message-ID') || '';
    const isBlock = await isMessageBlock(message, env);
    const isGuardian = GUARDIAN_MODE === 'true';
    const blockPolicy: BlockPolicy[] = (BLOCK_POLICY || 'telegram').split(',') as BlockPolicy[];
    const statusTTL = 60 * 60;
    const status = await dao.loadMailStatus(id, isGuardian);

    logger.info('Email received', {
        messageId: id,
        from: message.from,
        to: message.to,
        subject: message.headers.get('Subject') || '',
        isBlock,
        isGuardian,
        blockPolicy,
    });

    // Reject the email
    if (isBlock && blockPolicy.includes('reject')) {
        logger.info('Email rejected', { messageId: id, reason: 'block_policy_reject' });
        message.setReject('Blocked');
        return;
    }

    // Forward to email
    try {
        const blockForward = isBlock && blockPolicy.includes('forward');
        const forwardList = blockForward ? [] : (FORWARD_LIST || '').split(',');
        for (const forward of forwardList) {
            try {
                const add = forward.trim();
                if (status.forward.includes(add)) {
                    continue;
                }
                await message.forward(add);
                logger.info('Email forwarded', { messageId: id, forwardTo: add });
                if (isGuardian) {
                    status.forward.push(add);
                    await dao.saveMailStatus(id, status, statusTTL);
                }
            } catch (e) {
                logger.error('Forward failed', { messageId: id, forwardTo: forward, error: (e as Error).message });
            }
        }
    } catch (e) {
        logger.error('Forward handler error', { messageId: id, error: (e as Error).message });
    }

    // Parse email once for both webhook and Telegram
    let mail: EmailCache | null = null;
    try {
        const ttl = Number.parseInt(MAIL_TTL, 10) || 60 * 60 * 24;
        const maxSize = Number.parseInt(MAX_EMAIL_SIZE || '', 10) || 512 * 1024;
        const maxSizePolicy = MAX_EMAIL_SIZE_POLICY || 'truncate';
        mail = await parseEmail(message, maxSize, maxSizePolicy);
        await dao.saveMailCache(mail.id, mail, ttl);
        logger.info('Email parsed', { messageId: id, mailId: mail.id, subject: mail.subject });
    } catch (e) {
        logger.error('Email parse error', { messageId: id, error: (e as Error).message });
    }

    // Send to webhooks
    if (mail) {
        try {
            const blockWebhook = isBlock && blockPolicy.includes('webhook');
            if (!blockWebhook && WEBHOOK_LIST) {
                const newlyDelivered = await sendMailToWebhooks(mail, env, status.webhook);
                logger.info('Webhooks delivered', { mailId: mail.id, urls: newlyDelivered });
                if (isGuardian && newlyDelivered.length > 0) {
                    status.webhook.push(...newlyDelivered);
                    await dao.saveMailStatus(id, status, statusTTL);
                }
            }
        } catch (e) {
            logger.error('Webhook handler error', { mailId: mail.id, error: (e as Error).message });
        }
    }

    // Send to Telegram
    try {
        const blockTelegram = isBlock && blockPolicy.includes('telegram');
        if (!status.telegram && !blockTelegram && mail) {
            const ttl = Number.parseInt(MAIL_TTL, 10) || 60 * 60 * 24;
            const msgIDs = await sendMailToTelegram(mail, env);
            logger.info('Telegram message sent', { mailId: mail.id, messageIds: msgIDs });
            for (const msgID of msgIDs) {
                await dao.saveTelegramIDToMailID(`${msgID}`, mail.id, ttl);
            }
        }
        if (isGuardian) {
            status.telegram = true;
            await dao.saveMailStatus(id, status, statusTTL);
        }
    } catch (e) {
        logger.error('Telegram handler error', { mailId: mail?.id, error: (e as Error).message });
    }
}
