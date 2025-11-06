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
 * Required action that verifies user's email by sending a verification code.
 */
public class VerifyEmailByCode implements RequiredActionProvider, RequiredActionFactory, ServerInfoAwareProviderFactory {

    /** Provider ID for this required action */
    public static final String VERIFY_EMAIL_CODE = "VERIFY_EMAIL_CODE";
    
    /** Authentication session note key for email verification timestamp */
    public static final String VERIFY_EMAIL_CODE_TS = VERIFY_EMAIL_CODE + "_ts";
    
    /** Form parameter name for the email verification code */
    public static final String EMAIL_CODE = "email_code";
    
    /** Error message key for invalid verification code */
    public static final String INVALID_CODE = "VerifyEmailInvalidCode";
    
    /** Template name for the verification code input form */
    public static final String LOGIN_VERIFY_EMAIL_CODE_TEMPLATE = "login-verify-email-code.ftl";
    
    /** Configuration key for the length of the verification code */
    public static final String CONFIG_CODE_LENGTH = "code-length";
    
    /** Configuration key for the character set used to generate the code */
    public static final String CONFIG_CODE_SYMBOLS = "code-symbols";
    
    /** Default length of the verification code */
    public static final int DEFAULT_CODE_LENGTH = 8;
    
    /** Default character set for the verification code (alphanumeric) */
    public static final String DEFAULT_CODE_SYMBOLS = String.valueOf(SecretGenerator.ALPHANUM);

    private static final Logger logger = Logger.getLogger(VerifyEmailByCode.class);
    private int codeLength;
    private String codeSymbols;

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
            context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE_TS);
            context.success();
            return;
        }

        String email = context.getUser().getEmail();
        if (Validation.isBlank(email)) {
            context.ignore();
            return;
        }

        String storedCode = context.getAuthenticationSession().getAuthNote(VERIFY_EMAIL_CODE);
        String storedTimeStr = context.getAuthenticationSession().getAuthNote(VERIFY_EMAIL_CODE_TS);

        // 检查验证码是否过期（5分钟）
        if (storedCode != null && storedTimeStr != null) {
            try {
                long sentAt = Long.parseLong(storedTimeStr);
                long now = System.currentTimeMillis();
                if (now - sentAt > 5 * 60 * 1000) {
                    // 过期，清除
                    context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE);
                    context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE_TS);
                    storedCode = null;
                }
            } catch (NumberFormatException e) {
                // 时间戳无效，视为过期
                context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE);
                context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE_TS);
                storedCode = null;
            }
        }

        if (storedCode == null) {
            sendVerifyEmailAndCreateForm(context);
        } else {
            createFormChallenge(context, null);
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent().clone().event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, context.getUser().getEmail());
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        // 处理重发请求
        if ("true".equals(formData.getFirst("resend"))) {
            context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE);
            context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE_TS);
            sendVerifyEmailAndCreateForm(context);
            return;
        }

        String code = context.getAuthenticationSession().getAuthNote(VERIFY_EMAIL_CODE);
        if (code == null) {
            requiredActionChallenge(context);
            return;
        }

        String emailCode = formData.getFirst(EMAIL_CODE);
        if (!code.equals(emailCode)) {
            createFormChallenge(context, new FormMessage(EMAIL_CODE, INVALID_CODE));
            event.error(INVALID_CODE);
            return;
        }

        context.getUser().setEmailVerified(true);
        context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE);
        context.getAuthenticationSession().removeAuthNote(VERIFY_EMAIL_CODE_TS);
        event.success();
        context.success();
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
        codeLength = config.getInt(CONFIG_CODE_LENGTH, DEFAULT_CODE_LENGTH);
        codeSymbols = config.get(CONFIG_CODE_SYMBOLS, DEFAULT_CODE_SYMBOLS);
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

    private void sendVerifyEmailAndCreateForm(RequiredActionContext context) {
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        EventBuilder event = context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail());

        String code = SecretGenerator.getInstance().randomString(codeLength, codeSymbols.toCharArray());
        long now = System.currentTimeMillis();

        authSession.setAuthNote(VERIFY_EMAIL_CODE, code);
        authSession.setAuthNote(VERIFY_EMAIL_CODE_TS, String.valueOf(now));

        RealmModel realm = session.getContext().getRealm();
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);

        LoginFormsProvider form = context.form();
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

        createFormChallenge(context, null);
    }

    @Override
    public String getDisplayText() {
        return "Verify Email by code";
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        Map<String, String> ret = new LinkedHashMap<>();
        ret.put(VERIFY_EMAIL_CODE + "." + CONFIG_CODE_LENGTH, String.valueOf(codeLength));
        ret.put(VERIFY_EMAIL_CODE + "." + CONFIG_CODE_SYMBOLS, codeSymbols);
        return ret;
    }
}