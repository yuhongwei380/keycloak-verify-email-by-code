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
import org.keycloak.models.AuthenticationExecutionModel;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.authentication.RequiredActionContext;
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
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Required action to verify email using a time-limited code sent via email.
 * Supports dynamic configuration in Keycloak Admin Console.
 */
public class VerifyEmailByCode implements RequiredActionProvider,
        ConfigurableAuthenticatorFactory,
        ServerInfoAwareProviderFactory {

    public static final String VERIFY_EMAIL_CODE = "VERIFY_EMAIL_CODE";
    public static final String VERIFY_EMAIL_CODE_TIMESTAMP = "VERIFY_EMAIL_CODE_TIMESTAMP";
    public static final String EMAIL_CODE = "email_code";
    public static final String INVALID_CODE = "VerifyEmailInvalidCode";
    public static final String LOGIN_VERIFY_EMAIL_CODE_TEMPLATE = "login-verify-email-code.ftl";

    // Config keys
    public static final String CONFIG_CODE_LENGTH = "code-length";
    public static final String CONFIG_CODE_SYMBOLS = "code-symbols";
    public static final String CONFIG_CODE_TTL = "code-ttl"; // in seconds

    // Defaults
    public static final int DEFAULT_CODE_LENGTH = 8;
    public static final String DEFAULT_CODE_SYMBOLS = String.valueOf(SecretGenerator.ALPHANUM);
    public static final long DEFAULT_CODE_TTL_SECONDS = 300; // 5 minutes

    private static final Logger logger = Logger.getLogger(VerifyEmailByCode.class);

    // --- RequiredActionProvider methods ---

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
        if (context.getRealm().isVerifyEmail() && !context.getUser().isEmailVerified()) {
            context.getUser().addRequiredAction(VERIFY_EMAIL_CODE);
            logger.debug("User is required to verify email");
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (context.getUser().isEmailVerified()) {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            authSession.removeAuthNote(VERIFY_EMAIL_CODE);
            authSession.removeAuthNote(VERIFY_EMAIL_CODE_TIMESTAMP);
            context.success();
            return;
        }

        String email = context.getUser().getEmail();
        if (Validation.isBlank(email)) {
            context.ignore();
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String existingCode = authSession.getAuthNote(VERIFY_EMAIL_CODE);
        String timestampStr = authSession.getAuthNote(VERIFY_EMAIL_CODE_TIMESTAMP);
        long codeTtlMillis = getCodeTtlMillis(context);

        boolean codeValid = false;
        if (existingCode != null && timestampStr != null) {
            try {
                long sendTime = Long.parseLong(timestampStr);
                if (System.currentTimeMillis() - sendTime < codeTtlMillis) {
                    codeValid = true;
                }
            } catch (NumberFormatException ignored) {
                // invalid timestamp → treat as expired
            }
        }

        if (codeValid) {
            createFormChallenge(context, null);
        } else {
            sendVerifyEmailAndCreateForm(context);
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent().clone().event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, context.getUser().getEmail());
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        String code = authSession.getAuthNote(VERIFY_EMAIL_CODE);
        String timestampStr = authSession.getAuthNote(VERIFY_EMAIL_CODE_TIMESTAMP);
        long codeTtlMillis = getCodeTtlMillis(context);

        boolean codeExpired = true;
        if (code != null && timestampStr != null) {
            try {
                long sendTime = Long.parseLong(timestampStr);
                if (System.currentTimeMillis() - sendTime < codeTtlMillis) {
                    codeExpired = false;
                }
            } catch (NumberFormatException ignored) {
            }
        }

        if (code == null || codeExpired) {
            requiredActionChallenge(context);
            event.error("code_expired_or_missing");
            return;
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
        authSession.removeAuthNote(VERIFY_EMAIL_CODE_TIMESTAMP);
        event.success();
        context.success();
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    // --- ConfigurableAuthenticatorFactory methods ---

    @Override
    public String getId() {
        return VERIFY_EMAIL_CODE;
    }

    @Override
    public String getDisplayText() {
        return "Verify Email by code";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = Arrays.asList(
        new ProviderConfigProperty(
            CONFIG_CODE_LENGTH,
            "Code Length",
            "Length of the verification code (e.g., 6)",
            ProviderConfigProperty.STRING_TYPE,
            String.valueOf(DEFAULT_CODE_LENGTH)
        ),
        new ProviderConfigProperty(
            CONFIG_CODE_SYMBOLS,
            "Code Symbols",
            "Characters allowed in the code (e.g., 0123456789)",
            ProviderConfigProperty.STRING_TYPE,
            DEFAULT_CODE_SYMBOLS
        ),
        new ProviderConfigProperty(
            CONFIG_CODE_TTL,
            "Code TTL (seconds)",
            "Time-to-live of the verification code in seconds (e.g., 300)",
            ProviderConfigProperty.STRING_TYPE,
            String.valueOf(DEFAULT_CODE_TTL_SECONDS)
        )
    );

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    // --- Helper methods for config parsing ---

    private int getCodeLength(RequiredActionContext context) {
        String val = getAuthenticatorConfigProperty(context, CONFIG_CODE_LENGTH);
        return parsePositiveInt(val, DEFAULT_CODE_LENGTH);
    }

    private String getCodeSymbols(RequiredActionContext context) {
        String val = getAuthenticatorConfigProperty(context, CONFIG_CODE_SYMBOLS);
        return (val != null && !val.isEmpty()) ? val : DEFAULT_CODE_SYMBOLS;
    }

    private long getCodeTtlMillis(RequiredActionContext context) {
        String val = getAuthenticatorConfigProperty(context, CONFIG_CODE_TTL);
        long seconds = parsePositiveLong(val, DEFAULT_CODE_TTL_SECONDS);
        return Math.max(1000, seconds * 1000); // min 1 second
    }

    private String getAuthenticatorConfigProperty(RequiredActionContext context, String key) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        if (configModel != null && configModel.getConfig() != null) {
            return configModel.getConfig().get(key);
        }
        return null;
    }

    private static int parsePositiveInt(String str, int defaultValue) {
        if (str == null || str.trim().isEmpty()) return defaultValue;
        try {
            int val = Integer.parseInt(str.trim());
            return val > 0 ? val : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static long parsePositiveLong(String str, long defaultValue) {
        if (str == null || str.trim().isEmpty()) return defaultValue;
        try {
            long val = Long.parseLong(str.trim());
            return val > 0 ? val : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    // --- Email sending logic ---

    private void sendVerifyEmailAndCreateForm(RequiredActionContext context) {
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        EventBuilder event = context.getEvent().clone()
                .event(EventType.SEND_VERIFY_EMAIL)
                .detail(Details.EMAIL, user.getEmail());

        int codeLength = getCodeLength(context);
        String codeSymbols = getCodeSymbols(context);
        String code = SecretGenerator.getInstance().randomString(codeLength, codeSymbols.toCharArray());
        long timestamp = System.currentTimeMillis();

        authSession.setAuthNote(VERIFY_EMAIL_CODE, code);
        authSession.setAuthNote(VERIFY_EMAIL_CODE_TIMESTAMP, String.valueOf(timestamp));

        RealmModel realm = session.getContext().getRealm();
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);

        LoginFormsProvider form = context.form();
        try {
            session.getProvider(EmailTemplateProvider.class)
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

    // --- ServerInfoAwareProviderFactory ---

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // Optional: global fallback (not used when dynamic config is set)
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        // Operational info is per-instance, but config is dynamic.
        // We cannot show effective config here reliably.
        // Return empty or static defaults if needed.
        Map<String, String> ret = new LinkedHashMap<>();
        ret.put("default." + CONFIG_CODE_LENGTH, String.valueOf(DEFAULT_CODE_LENGTH));
        ret.put("default." + CONFIG_CODE_SYMBOLS, DEFAULT_CODE_SYMBOLS);
        ret.put("default." + CONFIG_CODE_TTL, String.valueOf(DEFAULT_CODE_TTL_SECONDS));
        return ret;
    }
}
