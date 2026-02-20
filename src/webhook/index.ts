import type { EmailCache, Environment } from '../types';

interface WebhookPayload {
    event: 'email.received';
    timestamp: string;
    data: {
        id: string;
        messageId: string;
        from: string;
        to: string;
        subject: string;
        text?: string;
        html?: string;
    };
}

async function computeHmacSha256(message: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const messageData = encoder.encode(message);

    const key = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, messageData);
    const hexArray = Array.from(new Uint8Array(signature));
    return hexArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function sendToWebhook(
    url: string,
    mail: EmailCache,
    secret?: string,
    timeoutMs: number = 5000
): Promise<void> {
    const payload: WebhookPayload = {
        event: 'email.received',
        timestamp: new Date().toISOString(),
        data: {
            id: mail.id,
            messageId: mail.messageId,
            from: mail.from,
            to: mail.to,
            subject: mail.subject,
            text: mail.text,
            html: mail.html,
        },
    };

    const headers: HeadersInit = {
        'Content-Type': 'application/json',
        'User-Agent': 'mail2telegram-webhook/1.0',
    };

    if (secret) {
        const payloadStr = JSON.stringify(payload);
        const signature = await computeHmacSha256(payloadStr, secret);
        headers['X-Webhook-Secret'] = secret;
        headers['X-Webhook-Signature'] = `sha256=${signature}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload),
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new Error(`Webhook returned ${response.status}: ${response.statusText}`);
        }
    } finally {
        clearTimeout(timeoutId);
    }
}

export async function sendMailToWebhooks(
    mail: EmailCache,
    env: Environment,
    deliveredUrls: string[]
): Promise<string[]> {
    const { WEBHOOK_LIST, WEBHOOK_SECRET, WEBHOOK_TIMEOUT } = env;

    if (!WEBHOOK_LIST) {
        return [];
    }

    const webhookUrls = WEBHOOK_LIST.split(',').map(url => url.trim()).filter(url => url);
    const timeoutMs = WEBHOOK_TIMEOUT ? Number.parseInt(WEBHOOK_TIMEOUT, 10) : 5000;
    const newlyDelivered: string[] = [];

    for (const url of webhookUrls) {
        if (deliveredUrls.includes(url)) {
            continue;
        }

        try {
            await sendToWebhook(url, mail, WEBHOOK_SECRET, timeoutMs);
            newlyDelivered.push(url);
        } catch (e) {
            console.error(`Failed to send webhook to ${url}:`, e);
        }
    }

    return newlyDelivered;
}
