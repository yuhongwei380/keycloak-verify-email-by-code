<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true displayMessage=!messagesPerField.exists('email_code'); section>
    <#if section = "header">
        ${msg("emailVerifyTitle")}
    <#elseif section = "form">
        <p class="instruction">${msg("emailVerifyInstruction1", user.email)}</p>
        <form id="kc-verify-email-code-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!} ${messagesPerField.printIfExists('email_code',properties.kcFormGroupErrorClass!)}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="email_code" class="${properties.kcLabelClass!}">${msg("email_code")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="email_code" name="email_code" class="${properties.kcInputClass!}"
                           aria-invalid="<#if messagesPerField.exists('email_code')>true</#if>" />

                    <#if messagesPerField.exists('email_code')>
                        <span id="input-error-email_code" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('email_code'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                        <div class="${properties.kcNoteClass!}" style="margin-top: 20px; font-size: 0.9em;">
                            ${msg("emailNotReceived")}
                            <a href="#" id="resendLink" class="${properties.kcLinkClass!}" onclick="resendCode(event)">
                                ${msg("doClickHere")}
                            </a>
                            <span id="countdown" style="color: #888; margin-left: 5px; font-size: 0.9em; display: none;"></span>
                        </div>
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <#if isAppInitiatedAction??>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                               type="submit" value="${msg("doSubmit")}"/>
                        <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                type="submit" name="cancel-aia" value="true">${msg("doCancel")}</button>
                    <#else>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                               type="submit" value="${msg("doSubmit")}"/>
                    </#if>
                </div>
            </div>
        </form>

        <!-- ✅ AJAX + 倒计时 JS（方案 A） -->
        <script>
            const RESEND_COOLDOWN = 60; // 60秒
            let countdownTimer = null;

            function startCountdown(remaining) {
                const link = document.getElementById('resendLink');
                const countdown = document.getElementById('countdown');
                if (!link || !countdown) return;

                let cooldown = remaining;
                if (cooldown <= 0) {
                    link.style.pointerEvents = 'auto';
                    link.style.opacity = '1';
                    link.style.textDecoration = 'underline';
                    countdown.style.display = 'none';
                    return;
                }

                link.style.pointerEvents = 'none';
                link.style.opacity = '0.6';
                link.style.textDecoration = 'none';
                countdown.style.display = 'inline';
                countdown.textContent = '(' + cooldown + 's)';

                countdownTimer = setInterval(() => {
                    cooldown--;
                    countdown.textContent = '(' + cooldown + 's)';
                    if (cooldown <= 0) {
                        clearInterval(countdownTimer);
                        link.style.pointerEvents = 'auto';
                        link.style.opacity = '1';
                        link.style.textDecoration = 'underline';
                        countdown.style.display = 'none';
                    }
                }, 1000);
            }

            function resendCode(event) {
                event.preventDefault();
                const link = document.getElementById('resendLink');
                if (link.style.pointerEvents === 'none') return;

                // 创建表单数据
                const formData = new FormData();
                formData.append('resend', 'true');

                // 发送 AJAX 请求
                fetch('${url.loginAction}', {
                    method: 'POST',
                    body: formData
                })
                .then(response => {
                    if (response.ok) {
                        // ✅ 关键：记录本次发送时间为当前客户端时间（毫秒字符串）
                        window.emailCodeSentAt = Date.now().toString();
                        // 启动新的60秒倒计时
                        if (countdownTimer) clearInterval(countdownTimer);
                        startCountdown(RESEND_COOLDOWN);
                    } else {
                        throw new Error('Server returned non-OK status');
                    }
                })
                .catch(error => {
                    console.error('Resend email failed:', error);
                    // 恢复按钮状态
                    if (countdownTimer) clearInterval(countdownTimer);
                    link.style.pointerEvents = 'auto';
                    link.style.opacity = '1';
                    link.style.textDecoration = 'underline';
                    const countdown = document.getElementById('countdown');
                    if (countdown) countdown.style.display = 'none';
                    // 可选：显示错误提示
                    alert("${msg("errorResendEmail")}");
                });
            }

            // ✅ 页面加载时初始化倒计时
            document.addEventListener('DOMContentLoaded', function() {
                // 优先使用客户端记录的时间戳（AJAX 重发后）
                let sentAtStr = window.emailCodeSentAt;
                // 其次使用服务端渲染的时间戳（首次进入）
                if (!sentAtStr || isNaN(sentAtStr)) {
                    sentAtStr = '${emailCodeSentAt!""}';
                }

                if (sentAtStr && !isNaN(sentAtStr)) {
                    const sentAt = parseInt(sentAtStr, 10);
                    const now = Date.now();
                    const elapsed = Math.floor((now - sentAt) / 1000);
                    const remaining = Math.max(0, RESEND_COOLDOWN - elapsed);
                    startCountdown(remaining);
                } else {
                    // 安全兜底：启动完整倒计时
                    startCountdown(RESEND_COOLDOWN);
                }
            });
        </script>
    <#elseif section = "info">
        <!-- 留空，避免重复显示 -->
    </#if>
</@layout.registrationLayout>