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
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.VisibleForTesting;
import android.util.Log;
import com.uber.sdk.android.core.BuildConfig;
import com.uber.sdk.android.core.Deeplink;
import com.uber.sdk.android.core.utils.AppProtocol;
import com.uber.sdk.core.auth.Scope;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static com.uber.sdk.android.core.SupportedAppType.UBER;
import static com.uber.sdk.android.core.SupportedAppType.UBER_EATS;
import static com.uber.sdk.android.core.UberSdk.UBER_SDK_LOG_TAG;
import static com.uber.sdk.android.core.utils.Preconditions.checkNotEmpty;
import static com.uber.sdk.android.core.utils.Preconditions.checkNotNull;
import static com.uber.sdk.android.core.utils.Preconditions.checkState;

/**
 * Provides deep link to login into the installed Uber app. For a simpler integration see
 * {@link LoginButton} or {@link LoginManager#login(Activity)}.
 */
public class SsoDeeplink implements Deeplink {

    public static final int DEFAULT_REQUEST_CODE = LoginManager.REQUEST_CODE_LOGIN_DEFAULT;

    @VisibleForTesting
    static final int MIN_UBER_RIDES_VERSION_SUPPORTED = 31302;
    @VisibleForTesting
    static final int MIN_UBER_EATS_VERSION_SUPPORTED = 983;

    @VisibleForTesting
    static final int MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED = 31302;
    @VisibleForTesting
    static final int MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED = 983;

    private static final String URI_QUERY_CLIENT_ID = "client_id";
    private static final String URI_QUERY_SCOPE = "scope";
    private static final String URI_QUERY_PLATFORM = "sdk";
    private static final String URI_QUERY_SDK_VERSION = "sdk_version";
    private static final String URI_QUERY_FLOW_TYPE = "flow_type";
    private static final String URI_QUERY_REDIRECT = "redirect_uri";
    private static final String URI_HOST = "connect";

    private final Activity activity;
    private final AppProtocol appProtocol;
    private final String clientId;
    private final String redirectUri;
    private final Collection<Scope> requestedScopes;
    private final Collection<String> requestedCustomScopes;
    private final int requestCode;

    private SsoDeeplink(
            @NonNull Activity activity,
            @NonNull AppProtocol appProtocol,
            @NonNull String clientId,
            @NonNull String redirectUri,
            @NonNull Collection<Scope> requestedScopes,
            @NonNull Collection<String> requestedCustomScopes,
            int requestCode) {
        this.activity = activity;
        this.appProtocol = appProtocol;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.requestCode = requestCode;
        this.requestedScopes = requestedScopes;
        this.requestedCustomScopes = requestedCustomScopes;
    }

    /**
     * {@code flowVersion} defaults to {@link FlowVersion#DEFAULT}
     *
     * @see #execute(FlowVersion)
     */
    @Override
    public void execute() {
        execute(FlowVersion.DEFAULT);
    }

    /**
     * Starts the deeplink with the configuration options specified by this object. Use {@link Builder} to construct
     * an instance.
     *
     * @param flowVersion specifies which client implementation to use for handling the response to the SSO request
     * @throws IllegalStateException if compatible Uber app is not installed or the deeplink is incorrectly configured.
     * Use {@link #isSupported()} to check.
     */
    void execute(@NonNull FlowVersion flowVersion) {
        checkState(isSupported(flowVersion), "Single sign on is not supported on the device. " +
                "Please install or update to the latest version of Uber app.");

        Intent intent = new Intent(Intent.ACTION_VIEW);
        final Uri deepLinkUri = createSsoUri(flowVersion);
        intent.setData(deepLinkUri);

        List<PackageInfo> validatedPackages = new ArrayList<>();

        validatedPackages.addAll(appProtocol.getInstalledPackages(activity, UBER, flowVersion.getMinSupportedRidesVersion()));
        validatedPackages.addAll(appProtocol.getInstalledPackages(activity, UBER_EATS, flowVersion.getMinSupportedEatsVersion()));

        if(!validatedPackages.isEmpty()) {
            intent.setPackage(validatedPackages.get(0).packageName);
        }
        if (flowVersion == FlowVersion.DEFAULT) {
            activity.startActivityForResult(intent, requestCode);
        } else {
            activity.startActivity(intent);
        }
    }

    private Uri createSsoUri(@NonNull FlowVersion flowVersion) {
        String scopes = AuthUtils.scopeCollectionToString(requestedScopes);
        if (!requestedCustomScopes.isEmpty()) {
            scopes = AuthUtils.mergeScopeStrings(scopes,
                    AuthUtils.customScopeCollectionToString(requestedCustomScopes));
        }
        Uri.Builder uriBuilder = new Uri.Builder().scheme(Deeplink.DEEPLINK_SCHEME)
                .authority(URI_HOST)
                .appendQueryParameter(URI_QUERY_CLIENT_ID, clientId)
                .appendQueryParameter(URI_QUERY_SCOPE, scopes)
                .appendQueryParameter(URI_QUERY_PLATFORM, AppProtocol.PLATFORM)
                .appendQueryParameter(URI_QUERY_FLOW_TYPE, flowVersion.name())
                .appendQueryParameter(URI_QUERY_REDIRECT, redirectUri)
                .appendQueryParameter(URI_QUERY_SDK_VERSION, BuildConfig.VERSION_NAME);
        return uriBuilder.build();
    }

    /**
     * {@code flowVersion} defaults to {@link FlowVersion#DEFAULT}
     *
     * @see #isSupported(FlowVersion)
     */
    @Override
    public boolean isSupported() {
        return isSupported(FlowVersion.DEFAULT);
    }

    /**
     * Check if SSO deep linking is supported in this device.
     *
     * @param flowVersion specifies which client implementation to validate
     * @return true if package name, minimum version, and redirect uri requirements for flowVersion are met
     */
    boolean isSupported(@NonNull FlowVersion flowVersion) {
        if (flowVersion == FlowVersion.REDIRECT_TO_SDK) {
            Intent redirectIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(redirectUri));
            redirectIntent.setPackage(activity.getPackageName());
            List<ResolveInfo> resolveInfoList = activity.getPackageManager().queryIntentActivities(
                    redirectIntent, PackageManager.MATCH_DEFAULT_ONLY);
            if (resolveInfoList.isEmpty()) {
                return false;
            }
        }

        return appProtocol.isInstalled(activity, UBER, flowVersion.getMinSupportedRidesVersion())
                || appProtocol.isInstalled(activity, UBER_EATS, flowVersion.getMinSupportedEatsVersion());
    }

    public static class Builder {

        private final Activity activity;
        private AppProtocol appProtocol;
        private String clientId;
        private String redirectUri;
        private Collection<Scope> requestedScopes;
        private Collection<String> requestedCustomScopes;
        private int requestCode = DEFAULT_REQUEST_CODE;

        public Builder(@NonNull Activity activity) {
            this.activity = activity;
        }

        public Builder clientId(@NonNull String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder scopes(@NonNull Scope... scopes) {
            this.requestedScopes = Arrays.asList(scopes);
            return this;
        }

        public Builder scopes(@NonNull Collection<Scope> scopes) {
            this.requestedScopes = scopes;
            return this;
        }

        public Builder customScopes(@NonNull Collection<String> customScopes) {
            this.requestedCustomScopes = customScopes;
            return this;
        }

        public Builder activityRequestCode(int requestCode) {
            this.requestCode = requestCode;
            return this;
        }

        @VisibleForTesting
        Builder appProtocol(@NonNull AppProtocol appProtocol) {
            this.appProtocol = appProtocol;
            return this;
        }

        Builder redirectUri(@NonNull String redirecUri) {
            this.redirectUri = redirecUri;
            return this;
        }

        public SsoDeeplink build() {
            checkNotNull(clientId, "Client Id must be set");

            checkNotEmpty(requestedScopes, "Scopes must be set.");

            if (requestedCustomScopes == null) {
                requestedCustomScopes = new ArrayList<>();
            }

            if (requestCode == DEFAULT_REQUEST_CODE) {
                Log.i(UBER_SDK_LOG_TAG, "Request code is not set, using default request code");
            }

            if (appProtocol == null) {
                appProtocol = new AppProtocol();
            }

            if (redirectUri == null) {
                redirectUri = activity.getPackageName().concat(".uberauth://redirect");
            }

            return new SsoDeeplink(activity,
                    appProtocol,
                    clientId,
                    redirectUri,
                    requestedScopes,
                    requestedCustomScopes,
                    requestCode);
        }
    }

    /**
     * Defines which client implementation of the SSO flow to use. This determines how the response from the SSO
     * request is returned to the calling application.
     */
    enum FlowVersion {
        DEFAULT(MIN_UBER_RIDES_VERSION_SUPPORTED, MIN_UBER_EATS_VERSION_SUPPORTED),
        REDIRECT_TO_SDK(MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED);

        private final int minSupportedRidesVersion;
        private final int minSupportedEatsVersion;

        FlowVersion(int minSupportedRidesVersion, int minSupportedEatsVersion) {
            this.minSupportedRidesVersion = minSupportedRidesVersion;
            this.minSupportedEatsVersion = minSupportedEatsVersion;
        }

        /**
         * @return the minimum version of the rides app that supports this FlowVersion
         */
        int getMinSupportedRidesVersion() {
            return this.minSupportedRidesVersion;
        }

        /**
         * @return the minimum version of the eats app that supports this FlowVersion
         */
        int getMinSupportedEatsVersion() {
            return this.minSupportedEatsVersion;
        }
    }
}
