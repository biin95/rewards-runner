/* Headless interactive login bot for Microsoft Rewards Script v5.
 * Automates sign-in in a display-less environment: fills email/password,
 * answers identity-confirmation with the configured recovery email, and asks
 * the terminal for the emailed one-time code. Saves sessions for both
 * platforms using the same SQLite storage the main script reads.
 *
 * Usage: node scripts/main/loginBot.mjs <account-email>
 */
import fs from 'node:fs'
import path from 'node:path'
import readline from 'node:readline/promises'
import { FingerprintGenerator } from 'fingerprint-generator'
import { chromium } from 'patchright'
import BROWSER_ARGS from '../lib/browser-args.json' with { type: 'json' }
import { buildBrowserProxy } from '../lib/proxy.cjs'
import {
    closeSessionDb,
    ensureSessionSchema,
    findAccountByEmail,
    getDirname,
    getProjectRoot,
    getSessionDbPath,
    loadAccountsFromEnv,
    loadConfig,
    openSessionDb,
    saveSessionRow
} from '../lib/commandUtils.js'
import { createSessionState } from '../../dist/session/SessionState.js'
import { resolveAccountLocale, fingerprintMatchesLocale } from '../../dist/util/Locale.js'
import { UserAgentManager } from '../../dist/browser/UserAgent.js'
import { browserLocaleArgs, fingerprintOperatingSystem } from '../../dist/browser/BrowserRuntime.js'
import { createAppIdentity } from '../../dist/rewards/app/AppIdentity.js'
import { getBingSignInEvidence } from '../../dist/browser/auth/LoginSession.js'
import { URLs } from '../../dist/constants/urls.js'

const REWARDS_LOGIN_URL = 'https://rewards.bing.com/auth/login'

// CI mode: no interactive terminal available; stop cleanly at OTP step
const CI_MODE = process.env.CI_LOGIN === 'true' || !process.stdin.isTTY

const S = {
    primaryButton: 'button[data-testid="primaryButton"]',
    secondaryButton: 'button[data-testid="secondaryButton"]',
    footerAction: '[data-testid="viewFooter"] [role="button"]',
    signInTile: '[data-testid="tile"]',
    emailIconOld: 'img[data-testid="accessibleImg"][src*="picker_verify_email"]',
    passwordTileOld: 'img[data-testid="accessibleImg"][src*="picker_verify_password"]',
    passwordlessOptionOld: 'img[data-testid="accessibleImg"][src*="picker_remote_ngc"]',
    recoveryEmail: '[data-testid="proof-confirmation"]',
    emailVerificationInput: 'input#proof-confirmation-email-input',
    accountLocked: '#serviceAbuseLandingTitle',
    errorAlert: 'div[role="alert"]',
    passwordEntry: '[data-testid="passwordEntry"]',
    passwordInput: 'input[type="password"]',
    emailEntry: 'input#usernameEntry',
    emailEntryOld: 'input[type="email"]',
    kmsiVideo: '[data-testid="kmsiVideo"]',
    otpCodeEntry: '[data-testid="codeEntry"]',
    otpInput: 'div[data-testid="codeEntry"] input, input[name="otc"], form[name="OneTimeCodeViewForm"] input',
    bingProfile: '#id_n'
}

import { execSync } from 'node:child_process'

const LOG_FILE = path.join(process.cwd(), 'login.log')
let lastUpload = 0
let uploading = false

function pushLogToRepo() {
    if (uploading) return
    uploading = true
    setTimeout(() => {
        try {
            const b64 = fs.readFileSync(LOG_FILE).toString('base64')
            const fname = `logs/login-${Math.floor(Date.now()/1000)}.log`
            execSync(`gh api -X PUT repos/biin95/Microsoft-Rewards-Script/contents/${fname} -f message=log -f content="${b64}"`, { stdio: 'ignore' })
        } catch {
            // silent: log upload is best-effort only
        } finally {
            uploading = false
        }
    }, 100)
}

const log = (level, msg) => {
    const line = `[${new Date().toISOString()}] [LOGIN-BOT] [${level}] ${msg}`
    console.log(line)
    try {
        fs.appendFileSync(LOG_FILE, line + '\n')
        if (Date.now() - lastUpload > 45000) {
            lastUpload = Date.now()
            pushLogToRepo()
        }
    } catch {
        // log file write is best-effort
    }
}

async function askQuestion(rl, question) {
    process.stdout.write('\n')
    const answer = (await rl.question(question)).trim()
    if (!answer) throw new Error('No answer provided')
    return answer
}

async function visible(page, selector, timeout = 4000) {
    try {
        await page.locator(selector).first().waitFor({ state: 'visible', timeout })
        return page.locator(selector).first()
    } catch {
        return null
    }
}

async function clickPrimary(page) {
    const btn = await visible(page, S.primaryButton, 5000)
    if (btn) {
        await btn.click()
        return true
    }
    const old = page.locator('input[type="submit"], button[type="submit"]').first()
    if (await old.isVisible().catch(() => false)) {
        await old.click()
        return true
    }
    return false
}

function createFingerprint(isMobile, locale) {
    return new FingerprintGenerator().getFingerprint({
        devices: isMobile ? ['mobile'] : ['desktop'],
        operatingSystems: isMobile ? ['android'] : [fingerprintOperatingSystem()],
        browsers: [{ name: 'chrome' }],
        locales: locale.acceptedLocales
    })
}

async function runAutomatedLogin({ page, account, isMobile }) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const email = account.email
    const password = account.password
    const recoveryEmail = account.recoveryEmail || email
    const statesSeen = new Set()

    try {
        for (let i = 0; i < 90; i++) {
            const url = page.url()
            const host = new URL(url).hostname
            const pageTitle = await page.title().catch(() => '')
            log('INFO', `poll#${i}: url=${url} | title="${pageTitle}"` )
            if (host === 'bing.com' || host.endsWith('.bing.com') || host === 'account.microsoft.com') {
                log('INFO', `Signed in (landed on ${host})`)
                return
            }

            await page.waitForTimeout(1500)

            if (await visible(page, S.accountLocked, 1500)) {
                throw new Error('Account locked (serviceAbuseLandingTitle) - sign-in aborted')
            }

            // Surface any error banner text so failures are diagnosable
            const alert = await visible(page, S.errorAlert, 800)
            if (alert && i % 3 === 0) {
                const alertText = (await alert.innerText().catch(() => '')).replace(/\s+/g, ' ').slice(0, 200)
                if (alertText) log('WARN', `ERROR_ALERT text: ${alertText}`)
            }

            // "Help us protect your account" / add-security-info pages:
            // prefer skipping; otherwise add an email proof so a code can be sent
            const skipBtn =
                (await visible(page, S.secondaryButton, 800)) ||
                (await visible(page, '#iShowSkip, #iCancel, a#iLandingViewSkip, button#SkipBtn', 800))
            if (skipBtn) {
                const skipText = (await skipBtn.innerText().catch(() => '')).toLowerCase()
                if (/skip|cancel|not now|稍后|跳过|no thanks/.test(skipText)) {
                    log(`INFO`, `SKIP button clicked ("${skipText}")`)
                    await skipBtn.click()
                    continue
                }
            } else {
                const addEmail =
                    (await visible(page, '#iSelectProofActionEmail', 800)) ||
                    (await visible(page, '[data-testid="addEmailProof"], button:has-text("Email"), button:has-text("电子邮件")', 800))
                if (addEmail) {
                    log('INFO', 'PROTECT_ACCOUNT: choosing add-email proof')
                    await addEmail.click()
                    continue
                }
            }

            // Legacy KMSI "stay signed in?" button
            const legacyKmsi = await visible(page, '#idSIButton9, #acceptButton', 800)
            if (legacyKmsi && /idSIButton9|acceptButton/.test(await legacyKmsi.evaluate(el => el.id))) {
                log('INFO', 'KMSI legacy: clicking yes/accept')
                await legacyKmsi.click()
                continue
            }

            // Email entry
            const emailBox = (await visible(page, S.emailEntry, 1500)) || (await visible(page, S.emailEntryOld, 1500))
            if (emailBox && !(await visible(page, S.passwordEntry, 500))) {
                log('INFO', 'EMAIL_INPUT: filling email')
                await emailBox.fill(email)
                await clickPrimary(page)
                statesSeen.add('email')
                continue
            }

            // Password entry
            const pwEntry = await visible(page, S.passwordEntry, 1500)
            if (pwEntry) {
                log('INFO', 'PASSWORD_INPUT: filling password')
                const pwBox = (await visible(page, S.passwordInput, 4000)) || pwEntry.locator('input').first()
                await pwBox.fill(password)
                await clickPrimary(page)
                statesSeen.add('password')
                continue
            }

            // Identity confirmation: enter recovery email proof
            const proofBox =
                (await visible(page, S.emailVerificationInput, 1500)) ||
                (await visible(page, S.recoveryEmail + ' input', 1500))
            if (proofBox) {
                log('INFO', 'IDENTITY_CONFIRM: filling recovery email proof')
                await proofBox.fill(recoveryEmail)
                await clickPrimary(page)
                continue
            }

            // One-time code entry
            const otpBox = await visible(page, S.otpCodeEntry, 1500)
            if (otpBox) {
                if (CI_MODE) {
                    throw new Error(`OTP_CODE_ENTRY reached: code sent to ${recoveryEmail}; url=${page.url()}; title="${await page.title().catch(() => '')}"`)
                }
                const code = await askQuestion(rl, `>>> 微软已发送验证码，请查收邮箱 ${recoveryEmail} 并输入验证码: `)
                log('INFO', 'OTP_CODE_ENTRY: filling code from terminal')
                const input = (await visible(page, S.otpInput, 4000)) || otpBox.locator('input').first()
                await input.fill(code)
                await clickPrimary(page)
                continue
            }

            // Sign-in method picker (password vs passwordless tiles)
            const pwTile = await visible(page, S.passwordTileOld, 1500)
            if (pwTile) {
                log('INFO', 'SIGN_IN_METHOD_PICKER: choosing password tile')
                await pwTile.click()
                continue
            }
            const emailTile = await visible(page, S.emailIconOld, 1500)
            if (emailTile && !statesSeen.has('email')) {
                log('INFO', 'SIGN_IN_METHOD_PICKER: choosing email tile')
                await emailTile.click()
                continue
            }

            // KMSI "stay signed in?" prompt
            const kmsi = await visible(page, S.kmsiVideo, 1500)
            if (kmsi) {
                log('INFO', 'KMSI_PROMPT: accepting stay-signed-in')
                await clickPrimary(page)
                continue
            }

            // Generic footer action fallback (e.g. "use your password instead")
            const footer = await visible(page, S.footerAction, 800)
            if (footer && !statesSeen.has('password') && statesSeen.has('email')) {
                const text = (await footer.innerText().catch(() => '')).toLowerCase()
                if (/password|密码/.test(text)) {
                    log('INFO', `FOOTER_ACTION: clicking "${text}"`)
                    await footer.click()
                    continue
                }
            }
        }
        throw new Error('Login did not complete within 60 polling cycles; last url: ' + page.url())
    } finally {
        rl.close()
    }
}

async function buildContext({ browser, fingerprint, isMobile, locale, storageState, userAgentManager, email }) {
    await userAgentManager.setEngineVersion(browser.version())
    await userAgentManager.updateFingerprintUserAgent(fingerprint, isMobile)
    const { newRewardsBrowserContext } = await import('../../dist/browser/RewardsBrowserContext.js')
    const screen = fingerprint.fingerprint.screen
    return newRewardsBrowserContext(browser, fingerprint, {
        permissions: [],
        ...(storageState ? { storageState } : {}),
        ...(isMobile
            ? {
                  isMobile: true,
                  hasTouch: true,
                  deviceScaleFactor: screen.devicePixelRatio,
                  viewport: { width: screen.width, height: screen.height },
                  screen: { width: screen.width, height: screen.height }
              }
            : {})
    })
}

async function saveBothSessions({ dbPath, email, cookies, locale, userAgentManager }) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 })
    const db = openSessionDb(dbPath)
    try {
        ensureSessionSchema(db)
        const storageState = createSessionState(cookies)
        for (const isMobile of [false, true]) {
            const fingerprint = createFingerprint(isMobile, locale)
            saveSessionRow(db, email, isMobile ? 'mobile' : 'desktop', storageState, fingerprint, true)
            log('SUCCESS', `Saved ${isMobile ? 'mobile' : 'desktop'} session | cookies=${storageState.cookies.length}`)
        }
        db.exec('PRAGMA wal_checkpoint(TRUNCATE)')
    } finally {
        closeSessionDb(db)
    }
}

async function main() {
    const emailArg = process.argv[2]
    if (!emailArg || !emailArg.includes('@')) {
        console.error('Usage: node scripts/main/loginBot.mjs <account-email>')
        process.exit(1)
    }

    const __dirname = getDirname(import.meta.url)
    const projectRoot = getProjectRoot(__dirname)

    const accounts = loadAccountsFromEnv(projectRoot)
    const account = findAccountByEmail(accounts, emailArg)
    if (!account) throw new Error(`No ACCOUNT_N_* block found in .env for ${emailArg}`)
    if (!account.password) throw new Error('ACCOUNT_N_PASSWORD missing in .env')

    const { data: config } = loadConfig(projectRoot)
    const { dbPath } = getSessionDbPath(projectRoot, config.sessionPath)
    log('INFO', `Session db: ${dbPath}`)

    const locale = resolveAccountLocale(account, undefined)
    const userAgentManager = new UserAgentManager({ appIdentity: createAppIdentity(account.email) })
    const proxy = buildBrowserProxy(account.proxy)

    const browser = await chromium.launch({
        headless: true,
        handleSIGINT: false,
        handleSIGTERM: false,
        ...(proxy ? { proxy } : {}),
        args: [...BROWSER_ARGS, ...browserLocaleArgs(locale)]
    })

    try {
        // ---- desktop pass: automated login ----
        const desktopFp = createFingerprint(false, locale)
        const desktopCtx = await buildContext({
            browser,
            fingerprint: desktopFp,
            isMobile: false,
            locale,
            userAgentManager,
            email: account.email
        })
        desktopCtx.setDefaultTimeout(60000)
        const page = await desktopCtx.newPage()
        log('INFO', `Opening ${REWARDS_LOGIN_URL}`)
        await page.goto(REWARDS_LOGIN_URL, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => log('WARN', `Initial nav: ${e.message}`))

        await runAutomatedLogin({ page, account, isMobile: false })

        // Verify Bing sign-in evidence
        log('INFO', 'Verifying Bing sign-in...')
        await page.goto(URLs.auth.bingSignIn, { waitUntil: 'domcontentloaded', timeout: 60000 })
        if (!(await getBingSignInEvidence(page, 60000))) {
            throw new Error('Bing sign-in could not be verified; nothing saved')
        }
        const cookies = await desktopCtx.cookies()
        if (!cookies.length) throw new Error('No cookies captured')
        log('INFO', `Captured ${cookies.length} cookies`)

        await saveBothSessions({ dbPath, email: account.email, cookies, locale, userAgentManager })
        log('SUCCESS', 'All sessions saved. You can close this Codespace.')
    } catch (error) {
        // Best-effort: persist whatever cookies exist so partial sign-ins are not wasted
        try {
            const ctx = browser.contexts()[0]
            if (ctx) {
                const partial = await ctx.cookies()
                if (partial.length) {
                    fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 })
                    const db = openSessionDb(dbPath)
                    try {
                        ensureSessionSchema(db)
                        const locale2 = resolveAccountLocale(account, undefined)
                        const fp = createFingerprint(false, locale2)
                        saveSessionRow(db, account.email, 'desktop', createSessionState(partial), fp, true)
                        log('WARN', `Partial sign-in saved: cookies=${partial.length} (desktop row only)`)
                    } finally {
                        closeSessionDb(db)
                    }
                }
            }
        } catch (saveErr) {
            log('WARN', `Best-effort save failed: ${saveErr?.message ?? saveErr}`)
        }
        throw error
    } finally {
        await browser.close().catch(() => undefined)
    }
}

main().catch(error => {
    log('ERROR', error?.message ?? String(error))
    process.exit(1)
})
