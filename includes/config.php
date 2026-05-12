<?php
declare(strict_types=1);

/*
 * Checker configuration
 */

const APP_NAME = 'checker';
const APP_VERSION = '1.2.0';

const APP_TITLE = 'Checker';
const APP_SUBTITLE = 'HTTP / HTTPS / SSL / TLS website checker';

const CONNECT_TIMEOUT = 5;
const HTTP_TIMEOUT = 8;
const TLS_TIMEOUT = 10;

const SSL_WARNING_DAYS = 14;

const USER_AGENT = APP_NAME . '/' . APP_VERSION;

const ALLOW_PRIVATE_IP_TARGETS = false;

const ENABLE_HTTP_HEADERS = true;
const ENABLE_RAW_JSON = true;
const ENABLE_COPY_JSON = true;
const ENABLE_TLS_DETAILS = true;

const DEFAULT_PLACEHOLDER = 'webtrash.ch';

const FOOTER_TEXT = APP_NAME . ' v' . APP_VERSION . ' · no shell execution · public hosts only';
