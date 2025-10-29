/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.redfroggy.keycloak.requiredactions;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilderException;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.freemarker.beans.ProfileBean;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class VerifyEmailByCode implements RequiredActionProvider, RequiredActionFactory, ServerInfoAwareProviderFactory {
    public static final String VERIFY_EMAIL_CODE = "VERIFY_EMAIL_CODE";
    public static final String EMAIL_CODE = "email_code";
    public static final String INVALID_CODE = "VerifyEmailInvalidCode";
    public static final String EXPIRED_CODE = "VerifyEmailExpiredCode"; // 保留，用于错误消息
    public static final String LOGIN_VERIFY_EMAIL_CODE_TEMPLATE = "login-verify-email-code.ftl";
    // 移除 CONFIG_* 常量
    public static final int DEFAULT_CODE_LENGTH = 8;
    public static final String DEFAULT_CODE_SYMBOLS = String.valueOf(SecretGenerator.ALPHANUM);
    public static final int DEFAULT_CODE_TTL_SECONDS = 300; // 5 minutes
    private static final Logger logger = Logger.getLogger(VerifyEmailByCode.class);
    // 移除实例变量 codeLength, codeSymbols, codeTtlSeconds
    // private int codeLength;
    // private String codeSymbols;
    // private int codeTtlSeconds;


    private static void createFormChallenge(RequiredActionContext context, FormMessage errorMessage) {
        LoginFormsProvider loginFormsProvider = context.form();
        if (Objects.nonNull(errorMessage)) {
            loginFormsProvider = loginFormsProvider.addError(new FormMessage(EMAIL_CODE, INVALID_CODE));
        }
        Response challenge = loginFormsProvider
                .setAttribute("user", new ProfileBean(context.getUser(), context.getSession()))
                .createForm(LOGIN_VERIFY_EMAIL_CODE_TEMPLATE);
        context.challenge(challenge);
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        if (context.getRealm().isVerifyEmail()
                && !context.getUser().isEmailVerified()) {
            context.getUser().addRequiredAction(VERIFY_EMAIL_CODE);
            logger.debug("User is required to verify email");
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (context.getUser().isEmailVerified()) {
            context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE);
            context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE + "_EXP"); // 确保清理过期时间
            context.success();
            return;
        }

        String email = context.getUser().getEmail();
        if (Validation.isBlank(email)) {
            context.ignore();
            return;
        }

        // Only send the code if it does not exist or is expired. This avoids resending on language switch.
        sendVerifyEmailIfNeededAndCreateForm(context);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent().clone().event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, context.getUser().getEmail());
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote(VERIFY_EMAIL_CODE);
        String expireAtMsStr = authSession.getAuthNote(VERIFY_EMAIL_CODE + "_EXP");
        if (code == null) {
            requiredActionChallenge(context); // Should not happen if UI is consistent, but handle gracefully
            return;
        }
        // Check expiration
        if (expireAtMsStr != null) {
            try {
                long expireAtMs = Long.parseLong(expireAtMsStr);
                if (System.currentTimeMillis() >= expireAtMs) {
                    createFormChallenge(context, new FormMessage(EMAIL_CODE, EXPIRED_CODE));
                    // regenerate and send a fresh code for the next attempt
                    sendNewVerificationCode(context);
                    return;
                }
            } catch (NumberFormatException ignored) {
                logger.warn("Stored expiration time for verification code is malformed, proceeding without expiration check.");
                // proceed without expiration if stored value is malformed
            }
        }
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String emailCode = formData.getFirst(EMAIL_CODE);

        if (!code.equals(emailCode)) {
            createFormChallenge(context, new FormMessage(EMAIL_CODE, INVALID_CODE));
            event.error(INVALID_CODE);
            return;
        }
        context.getUser().setEmailVerified(true);
        authSession.removeAuthNote(VERIFY_EMAIL_CODE);
        authSession.removeAuthNote(VERIFY_EMAIL_CODE + "_EXP");
        event.success();
        context.success();
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
        // 固定配置：不再从 Keycloak 控制台动态读取
        // 无需设置实例变量，直接在使用处引用 DEFAULT_* 常量
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return VERIFY_EMAIL_CODE;
    }

    private void sendVerifyEmailIfNeededAndCreateForm(RequiredActionContext context) throws UriBuilderException, IllegalArgumentException {
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        EventBuilder event = context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail());

        String existingCode = authSession.getAuthNote(VERIFY_EMAIL_CODE);
        String expireAtMsStr = authSession.getAuthNote(VERIFY_EMAIL_CODE + "_EXP");
        boolean shouldSend = true;
        long now = System.currentTimeMillis();
        if (existingCode != null && expireAtMsStr != null) {
            try {
                long expireAtMs = Long.parseLong(expireAtMsStr);
                if (now < expireAtMs) {
                    shouldSend = false; // still valid; don't resend
                }
            } catch (NumberFormatException ignored) {
                logger.warn("Stored expiration time for verification code is malformed, will regenerate code.");
                // fall through and regenerate
            }
        }
        String code;
        if (shouldSend) {
            code = SecretGenerator.getInstance().randomString(DEFAULT_CODE_LENGTH, DEFAULT_CODE_SYMBOLS.toCharArray());
            authSession.setAuthNote(VERIFY_EMAIL_CODE, code);
            long expireAtMs = now + (DEFAULT_CODE_TTL_SECONDS * 1000L);
            authSession.setAuthNote(VERIFY_EMAIL_CODE + "_EXP", String.valueOf(expireAtMs));
        } else {
            code = existingCode;
        }
        RealmModel realm = session.getContext().getRealm();

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);

        LoginFormsProvider form = context.form();
        if (shouldSend) {
            try {
                session
                        .getProvider(EmailTemplateProvider.class)
                        .setAuthenticationSession(authSession)
                        .setRealm(realm)
                        .setUser(user)
                        .send("emailVerificationSubject", "email-verification-with-code.ftl", attributes);
                event.success();
            } catch (EmailException e) {
                logger.error("Failed to send verification email", e);
                event.error(Errors.EMAIL_SEND_FAILED);
                form.setError(Errors.EMAIL_SEND_FAILED);
            }
        }

        createFormChallenge(context, null);
    }

    private void sendNewVerificationCode(RequiredActionContext context) {
        // Helper to regenerate and send a fresh code (used on expiration)
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.removeAuthNote(VERIFY_EMAIL_CODE);
        authSession.removeAuthNote(VERIFY_EMAIL_CODE + "_EXP");
        // Call sendVerifyEmailIfNeededAndCreateForm which will definitely send a new code now that old ones are removed
        sendVerifyEmailIfNeededAndCreateForm(context);
    }


    @Override
    public String getDisplayText() {
        logger.info("Retrieved display text for VerifyEmailByCode");
        return "Verify Email by code";
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        // 既然配置已固定，OperationalInfo 可以反映这一点，或者简化
        // 保持原有输出，但明确是固定值
        Map<String, String> ret = new LinkedHashMap<>();
        ret.put("Fixed Code Length", String.valueOf(DEFAULT_CODE_LENGTH));
        ret.put("Fixed Code Symbols", DEFAULT_CODE_SYMBOLS);
        ret.put("Fixed Code TTL (seconds)", String.valueOf(DEFAULT_CODE_TTL_SECONDS));
        return ret;
    }

    // 已移除控制台可配置项定义
}
