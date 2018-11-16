/*
 * Copyright (c) 2016 Uber Technologies, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.uber.sdk.android.core.auth;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.support.customtabs.CustomTabsIntent;
import android.text.TextUtils;
import android.webkit.WebView;

import com.uber.sdk.android.core.utils.CustomTabsHelper;
import com.uber.sdk.core.client.SessionConfiguration;

/**
 * {@link android.app.Activity} that shows web view for Uber user authentication and authorization.
 */
public class LoginActivity extends Activity {
    static final String EXTRA_RESPONSE_TYPE = "RESPONSE_TYPE";
    static final String EXTRA_SESSION_CONFIGURATION = "SESSION_CONFIGURATION";
    static final String EXTRA_SSO_ENABLED = "SSO_ENABLED";
    static final String EXTRA_CODE_VERIFIER = "CODE_VERIFIER";

    static final String ERROR = "error";

    private boolean authStarted;

    @VisibleForTesting
    WebView webView;

    @VisibleForTesting
    SsoDeeplinkFactory ssoDeeplinkFactory = new SsoDeeplinkFactory();

    @VisibleForTesting
    CustomTabsHelper customTabsHelper = new CustomTabsHelper();

    /**
     * Create an {@link Intent} to pass to this activity
     *
     * @param context the {@link Context} for the intent
     * @param sessionConfiguration to be used for gather clientId
     * @param responseType that is expected
     * @return an intent that can be passed to this activity
     */
    @NonNull
    static Intent newIntent(
            @NonNull Context context,
            @NonNull SessionConfiguration sessionConfiguration,
            @NonNull ResponseType responseType) {

        return newIntent(context, sessionConfiguration, responseType, false);
    }

    /**
     * Create an {@link Intent} to pass to this activity
     *
     * @param context the {@link Context} for the intent
     * @param sessionConfiguration to be used for gather clientId
     * @param responseType that is expected
     * @param isSsoEnabled specifies whether to attempt login with SSO
     * @return an intent that can be passed to this activity
     */
    @NonNull
    static Intent newIntent(
            @NonNull Context context,
            @NonNull SessionConfiguration sessionConfiguration,
            @NonNull ResponseType responseType,
            boolean isSsoEnabled) {

        return newIntent(context, sessionConfiguration, responseType, isSsoEnabled, null);
    }

    /**
     * Create an {@link Intent} to pass to this activity
     *
     * @param context the {@link Context} for the intent
     * @param sessionConfiguration to be used for gather clientId
     * @param responseType that is expected
     * @param isSsoEnabled specifies whether to attempt login with SSO
     * @return an intent that can be passed to this activity
     */
    @NonNull
    static Intent newIntent(
            @NonNull Context context,
            @NonNull SessionConfiguration sessionConfiguration,
            @NonNull ResponseType responseType,
            boolean isSsoEnabled,
            @Nullable String codeVerifier) {

        final Intent data = new Intent(context, LoginActivity.class)
                .putExtra(EXTRA_SESSION_CONFIGURATION, sessionConfiguration)
                .putExtra(EXTRA_RESPONSE_TYPE, responseType)
                .putExtra(EXTRA_SSO_ENABLED, isSsoEnabled)
                .putExtra(EXTRA_CODE_VERIFIER, codeVerifier);

        return data;
    }

    /**
     * Used to handle Redirect URI response from customtab or browser
     *
     * @param context
     * @param responseUri
     * @return
     */
    public static Intent newResponseIntent(Context context, Uri responseUri) {
        Intent intent = new Intent(context, LoginActivity.class);
        intent.setData(responseUri);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return intent;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        init();
    }

    @Override
    protected void onResume() {
        super.onResume();

        if(webView == null) {
            if(!authStarted) {
                authStarted = true;
                return;
            }

            finish();
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        authStarted = false;
        setIntent(intent);
        init();
    }

    protected void init() {
        if(getIntent().getData() != null) {
            handleResponse(getIntent().getData());
        } else {
            loadUrl();
        }
    }

    protected void loadUrl() {
        Intent intent = getIntent();

        SessionConfiguration sessionConfiguration = (SessionConfiguration) intent.getSerializableExtra(EXTRA_SESSION_CONFIGURATION);
        ResponseType responseType = (ResponseType) intent.getSerializableExtra(EXTRA_RESPONSE_TYPE);
        boolean isSsoEnabled = intent.getBooleanExtra(EXTRA_SSO_ENABLED, false);
        String codeVerifier = intent.getStringExtra(EXTRA_CODE_VERIFIER);

        if (!validateRequestParams(isSsoEnabled, sessionConfiguration, responseType, codeVerifier)) {
            return;
        }

        String redirectUri = sessionConfiguration.getRedirectUri() != null ? sessionConfiguration
                .getRedirectUri() : getApplicationContext().getPackageName() + "uberauth";

        if (isSsoEnabled) {
            SsoDeeplink ssoDeeplink = ssoDeeplinkFactory.getSsoDeeplink(this, sessionConfiguration);

            if (ssoDeeplink.isSupported(SsoDeeplink.FlowVersion.REDIRECT_TO_SDK)) {
                ssoDeeplink.execute(SsoDeeplink.FlowVersion.REDIRECT_TO_SDK);
            } else {
                onError(AuthenticationError.INVALID_REDIRECT_URI);
            }
            return;
        }

        String url = AuthUtils.buildUrl(redirectUri, responseType, sessionConfiguration, codeVerifier);
        loadChrometab(url);
    }

    protected boolean handleResponse(@NonNull Uri uri) {
        final String fragment = uri.getFragment();

        if (fragment == null) {
            onError(AuthenticationError.INVALID_RESPONSE);
            return true;
        }

        final Uri fragmentUri = new Uri.Builder().encodedQuery(fragment).build();

        // In case fragment contains error, we want to handle that too.
        final String error = fragmentUri.getQueryParameter(ERROR);
        if (!TextUtils.isEmpty(error)) {
            onError(AuthenticationError.fromString(error));
            return true;
        }

        onTokenReceived(fragmentUri);
        return true;
    }

    protected void loadChrometab(String url) {
        final CustomTabsIntent intent = new CustomTabsIntent.Builder().build();
        customTabsHelper.openCustomTab(this, intent, Uri.parse(url), new CustomTabsHelper
                .BrowserFallback());
    }

    void onError(@NonNull AuthenticationError error) {
        Intent data = new Intent();
        data.putExtra(LoginManager.EXTRA_ERROR, error.toStandardString());
        setResult(RESULT_CANCELED, data);
        finish();
    }

    void onTokenReceived(@NonNull Uri uri) {
        try {
            Intent data = AuthUtils.parseTokenUriToIntent(uri);

            setResult(RESULT_OK, data);
            finish();
        } catch (LoginAuthenticationException loginException) {
            onError(loginException.getAuthenticationError());
            return;
        }
    }

    private boolean validateRequestParams(
            boolean isSsoEnabled,
            @Nullable SessionConfiguration sessionConfiguration,
            @Nullable ResponseType responseType,
            @Nullable String codeVerifier) {
        if (sessionConfiguration == null) {
            onError(AuthenticationError.INVALID_PARAMETERS);
            return false;
        }

        if ((sessionConfiguration.getScopes() == null || sessionConfiguration.getScopes().isEmpty())
                && (sessionConfiguration.getCustomScopes() == null  || sessionConfiguration.getCustomScopes().isEmpty())) {
            onError(AuthenticationError.INVALID_SCOPE);
            return false;
        }

        if (responseType == null) {
            onError(AuthenticationError.INVALID_RESPONSE_TYPE);
            return false;
        }

        if (responseType == ResponseType.TOKEN && codeVerifier == null && !isSsoEnabled) {
            onError(AuthenticationError.INVALID_CODE_VERIFIER);
            return false;
        }

        return true;
    }
}
