// errors.js
// Pure helpers (no DOM, no fetch) that turn any failure into a clear,
// localised message for the user.  Tested with node:test.
//
// Sources of errors:
//   • JSON responses in the API's common format {ok:false, error, detail}
//   • SSE error events from /api/scan: {error: "<message>", status: <code>}
//   • Network failures (fetch rejected, EventSource dropped)

const MESSAGES = {
    unauthorized: {
        es: 'Sesión no válida o caducada: vuelve a introducir el token de acceso.',
        en: 'Session invalid or expired: please enter the access token again.',
    },
    ssrf_blocked: {
        es: '⛔ Destino bloqueado: resuelve a una dirección interna. Solo se permite en un laboratorio propio con ALLOW_PRIVATE_IPS=true.',
        en: '⛔ Target blocked: it resolves to an internal address. Only allowed in your own lab with ALLOW_PRIVATE_IPS=true.',
    },
    busy: {
        es: 'El servidor ya está ejecutando el máximo de operaciones de este tipo. Inténtalo de nuevo en unos segundos.',
        en: 'The server is already running the maximum number of these operations. Try again in a few seconds.',
    },
    rate_limited: {
        es: 'Demasiadas peticiones seguidas. Espera un momento y vuelve a intentarlo.',
        en: 'Too many requests. Wait a moment and try again.',
    },
    token_required: {
        es: 'El servidor escucha en una interfaz pública sin LUKITA_API_TOKEN y se niega a responder.',
        en: 'The server listens on a public interface without LUKITA_API_TOKEN and refuses to answer.',
    },
    invalid_host: {
        es: 'El servidor rechaza este nombre de host (LUKITA_ALLOWED_HOSTS).',
        en: 'The server rejects this host name (LUKITA_ALLOWED_HOSTS).',
    },
    payload_too_large: {
        es: 'La petición es demasiado grande.',
        en: 'The request is too large.',
    },
    screenshots_unavailable: {
        es: 'Las capturas no están disponibles en este servidor (Playwright no está instalado).',
        en: 'Screenshots are not available on this server (Playwright is not installed).',
    },
    network: {
        es: 'No se pudo contactar con el servidor. Comprueba que LukitaPort sigue en marcha.',
        en: 'Could not reach the server. Check that LukitaPort is still running.',
    },
    stream_lost: {
        es: 'Se perdió la conexión con el servidor durante el escaneo.',
        en: 'The connection to the server was lost during the scan.',
    },
    internal_error: {
        es: 'Error interno del servidor. Revisa los logs de LukitaPort.',
        en: 'Internal server error. Check the LukitaPort logs.',
    },
};

// Codes whose server "detail" is the useful part of the message.
const DETAIL_PREFIX = {
    validation_error: { es: 'Datos no válidos', en: 'Invalid input' },
    unresolvable:     { es: 'No se pudo resolver el objetivo', en: 'Could not resolve the target' },
    upstream_error:   { es: 'Servicio externo no disponible', en: 'External service unavailable' },
    pdf_failed:       { es: 'No se pudo generar el PDF', en: 'Could not generate the PDF' },
};

const STATUS_CODES = {
    0: 'network', 401: 'unauthorized', 403: 'ssrf_blocked', 413: 'payload_too_large',
    422: 'validation_error', 429: 'busy', 500: 'internal_error', 502: 'upstream_error',
    503: 'screenshots_unavailable',
};

/** Best-effort error code for an HTTP status when the body has none. */
export function codeForStatus(status) {
    return STATUS_CODES[status] || 'http_error';
}

/**
 * describeError — human message for {status, code, detail}.
 * `detail` is the server's text; it is used when it adds information.
 */
export function describeError({ status = 0, code, detail } = {}, lang = 'es') {
    const l = lang === 'en' ? 'en' : 'es';
    const c = code || codeForStatus(status);
    if (DETAIL_PREFIX[c]) {
        return detail ? `${DETAIL_PREFIX[c][l]}: ${detail}` : DETAIL_PREFIX[c][l];
    }
    if (MESSAGES[c]) return MESSAGES[c][l];
    if (detail) return detail;
    return l === 'es' ? `Error del servidor (HTTP ${status}).` : `Server error (HTTP ${status}).`;
}

/**
 * errorInfoFromSSE — map a /api/scan error event {error, status} to
 * {status, code, detail}.  SSE events carry a message, not a code.
 */
export function errorInfoFromSSE(event) {
    const status = Number(event?.status) || 0;
    let code = codeForStatus(status);
    // 503 on the scan stream means local resources ran out, 422 bad input:
    // both are explained by the server text.
    if (status === 503 || status === 422 || status === 400) code = 'scan_error';
    return { status, code, detail: event?.error || '' };
}

/** errorInfoFromBody — parse the API's common error format. */
export function errorInfoFromBody(status, body) {
    return {
        status,
        code:   (body && typeof body.error === 'string') ? body.error : codeForStatus(status),
        detail: (body && typeof body.detail === 'string') ? body.detail : '',
    };
}
