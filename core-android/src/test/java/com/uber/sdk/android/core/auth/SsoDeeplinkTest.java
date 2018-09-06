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
import android.content.pm.ResolveInfo;
import android.net.Uri;
import com.google.common.collect.Sets;
import com.uber.sdk.android.core.BuildConfig;
import com.uber.sdk.android.core.RobolectricTestBase;
import com.uber.sdk.android.core.auth.SsoDeeplink.FlowVersion;
import com.uber.sdk.android.core.utils.AppProtocol;

import com.uber.sdk.core.auth.Scope;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.robolectric.Robolectric;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.res.builder.RobolectricPackageManager;
import org.robolectric.shadows.ShadowResolveInfo;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import static com.uber.sdk.android.core.SupportedAppType.UBER;
import static com.uber.sdk.android.core.SupportedAppType.UBER_EATS;
import static com.uber.sdk.android.core.auth.SsoDeeplink.MIN_UBER_EATS_VERSION_SUPPORTED;
import static com.uber.sdk.android.core.auth.SsoDeeplink.MIN_UBER_RIDES_VERSION_SUPPORTED;
import static com.uber.sdk.android.core.auth.SsoDeeplink.MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED;
import static com.uber.sdk.android.core.auth.SsoDeeplink.MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

public class SsoDeeplinkTest extends RobolectricTestBase {

    private static final String CLIENT_ID = "MYCLIENTID";
    private static final Set<Scope> GENERAL_SCOPES = Sets.newHashSet(Scope.HISTORY, Scope.PROFILE);
    private static final int REQUEST_CODE = 1234;
    private static final String REDIRECT_URI = "com.example.app://redirect";

    private static final String DEFAULT_URI =
            "uber://connect?client_id=MYCLIENTID&scope=profile%20history&sdk=android&flow_type=DEFAULT"
                    + "&redirect_uri=com.example.app%3A%2F%2Fredirect&sdk_version="
                    + BuildConfig.VERSION_NAME;
    @Mock
    AppProtocol appProtocol;

    Activity activity;

    RobolectricPackageManager packageManager;

    ResolveInfo resolveInfo;

    Intent redirectIntent;

    SsoDeeplink ssoDeeplink;

    @Before
    public void setUp() {
        activity = spy(Robolectric.setupActivity(Activity.class));

        redirectIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(REDIRECT_URI));
        redirectIntent.setPackage(activity.getPackageName());
        resolveInfo = ShadowResolveInfo.newResolveInfo("", activity.getPackageName());
        packageManager = RuntimeEnvironment.getRobolectricPackageManager();
        packageManager.addResolveInfoForIntent(redirectIntent, resolveInfo);

        ssoDeeplink = new SsoDeeplink.Builder(activity)
                .clientId(CLIENT_ID)
                .scopes(GENERAL_SCOPES)
                .appProtocol(appProtocol)
                .activityRequestCode(REQUEST_CODE)
                .redirectUri(REDIRECT_URI)
                .build();
    }

    @Test
    public void isSupported_withRidesAppInstalled_andDefaultFlowVersion_andAboveMinDefaultFlowVersion_shouldBeTrue() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED)).thenReturn(true);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_SUPPORTED)).thenReturn(false);

        assertThat(ssoDeeplink.isSupported()).isTrue();

        verify(appProtocol).isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED);
    }

    @Test
    public void isSupported_withEatsAppInstalled_andAboveMinDefaultFlowVersion_shouldBeTrue() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED)).thenReturn(false);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_SUPPORTED)).thenReturn(true);

        assertThat(ssoDeeplink.isSupported()).isTrue();

        verify(appProtocol).isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED);
        verify(appProtocol).isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_SUPPORTED);
    }

    @Test
    public void isSupported_withBothAppsBelowMinDefaultFlowVersion_shouldBeFalse() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED)).thenReturn(false);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_SUPPORTED)).thenReturn(false);

        assertThat(ssoDeeplink.isSupported()).isFalse();

        verify(appProtocol).isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED);
        verify(appProtocol).isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_SUPPORTED);
    }

    @Test
    public void isSupported_withRedirectToSdkFlowVersion_andRidesAboveMinRedirectToSdkVersion_shouldBeTrue() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(true);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(false);

        assertThat(ssoDeeplink.isSupported(FlowVersion.REDIRECT_TO_SDK)).isTrue();

        verify(appProtocol).isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED);
    }

    @Test
    public void isSupported_withRedirectToSdkFlowVersion_andEatsAboveMinRedirectToSdkVersion_shouldBeTrue() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(false);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(true);

        assertThat(ssoDeeplink.isSupported(FlowVersion.REDIRECT_TO_SDK)).isTrue();

        verify(appProtocol).isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED);
        verify(appProtocol).isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED);
    }

    @Test
    public void isSupported_withRedirectToSdkFlowVersion_andBothAppsBelowMinRedirectToSdkVersion_shouldBeFalse() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(false);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(false);

        assertThat(ssoDeeplink.isSupported(FlowVersion.REDIRECT_TO_SDK)).isFalse();

        verify(appProtocol).isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED);
        verify(appProtocol).isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED);
    }

    @Test
    public void isSupported_withRedirectToSdkFlowVersion_andCantResolveRedirectIntent_shouldBeFalse() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(true);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(true);
        packageManager.removeResolveInfosForIntent(redirectIntent, activity.getPackageName());

        assertThat(ssoDeeplink.isSupported(FlowVersion.REDIRECT_TO_SDK)).isFalse();

        verify(appProtocol, never()).isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED);
        verify(appProtocol, never()).isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED);
    }

    @Test
    public void execute_withInstalledPackage_andDefaultFlow_shouldSetPackageAndStartActivityForResult() {
        String packageName = "PACKAGE_NAME";
        PackageInfo packageInfo = new PackageInfo();
        packageInfo.packageName = packageName;

        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED)).thenReturn(true);
        when(appProtocol.getInstalledPackages(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED))
                .thenReturn(Collections.singletonList(packageInfo));

        ssoDeeplink.execute();

        verify(appProtocol).getInstalledPackages(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED);
        verify(appProtocol).getInstalledPackages(activity, UBER_EATS, MIN_UBER_EATS_VERSION_SUPPORTED);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivityForResult(intentCaptor.capture(), eq(REQUEST_CODE));
        Intent intent = intentCaptor.getValue();

        assertThat(intent.getPackage()).isEqualTo(packageName);
        assertThat(intent.getData().toString()).isEqualTo(DEFAULT_URI);
    }

    @Test
    public void execute_withInstalledPackage_andRedirectToSdkFlow_shouldSetPackageAndStartActivity() {
        String packageName = "PACKAGE_NAME";
        PackageInfo packageInfo = new PackageInfo();
        packageInfo.packageName = packageName;

        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(true);
        when(appProtocol.getInstalledPackages(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED))
                .thenReturn(Collections.singletonList(packageInfo));

        ssoDeeplink.execute(FlowVersion.REDIRECT_TO_SDK);
        verify(appProtocol).getInstalledPackages(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED);
        verify(appProtocol).getInstalledPackages(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());
        Intent intent = intentCaptor.getValue();

        String expectedUri =
                "uber://connect?client_id=MYCLIENTID&scope=profile%20history&sdk=android&flow_type=REDIRECT_TO_SDK"
                        + "&redirect_uri=com.example.app%3A%2F%2Fredirect&sdk_version="
                        + BuildConfig.VERSION_NAME;

        assertThat(intent.getData().toString()).isEqualTo(expectedUri);
        assertThat(intent.getPackage()).isEqualTo(packageName);
    }

    @Test
    public void execute_withoutRequestCode_shouldUseDefaultRequestCode() {
        enableSupport(FlowVersion.DEFAULT);

        new SsoDeeplink.Builder(activity)
                .clientId(CLIENT_ID)
                .scopes(GENERAL_SCOPES)
                .appProtocol(appProtocol)
                .redirectUri(REDIRECT_URI)
                .build()
                .execute();

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        final ArgumentCaptor<Integer> requestCodeCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(activity).startActivityForResult(intentCaptor.capture(), requestCodeCaptor.capture());

        Uri uri = intentCaptor.getValue().getData();

        assertThat(uri.toString()).isEqualTo(DEFAULT_URI);
        assertThat(requestCodeCaptor.getValue()).isEqualTo(LoginManager.REQUEST_CODE_LOGIN_DEFAULT);
    }


    @Test(expected = IllegalStateException.class)
    public void execute_withoutScopes_shouldFail() {
        enableSupport(FlowVersion.DEFAULT);

        new SsoDeeplink.Builder(activity)
                .clientId(CLIENT_ID)
                .activityRequestCode(REQUEST_CODE)
                .appProtocol(appProtocol)
                .build()
                .execute();
    }

    @Test
    public void execute_withScopesAndCustomScopes_shouldSucceed() {
        enableSupport(FlowVersion.DEFAULT);

        Collection<String> collection = Arrays.asList("sample", "test");

        new SsoDeeplink.Builder(activity)
                .clientId(CLIENT_ID)
                .activityRequestCode(REQUEST_CODE)
                .scopes(GENERAL_SCOPES)
                .customScopes(collection)
                .appProtocol(appProtocol)
                .build()
                .execute();

        ArgumentCaptor<Intent> intentArgumentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivityForResult(intentArgumentCaptor.capture(), anyInt());

        Uri uri = intentArgumentCaptor.getValue().getData();
        assertThat(uri.getQueryParameter("scope")).contains("history", "profile", "sample", "test");
    }

    @Test(expected = NullPointerException.class)
    public void execute_withoutClientId_shouldFail() {
        enableSupport(FlowVersion.DEFAULT);

        new SsoDeeplink.Builder(activity)
                .scopes(GENERAL_SCOPES)
                .activityRequestCode(REQUEST_CODE)
                .appProtocol(appProtocol)
                .build()
                .execute();
    }

    @Test
    public void execute_withoutRedirectUri_shouldUseDefaultUri() {
        enableSupport(FlowVersion.REDIRECT_TO_SDK);
        packageManager.removeResolveInfosForIntent(redirectIntent, activity.getPackageName());
        String expectedRedirectUri = activity.getPackageName().concat(".uberauth://redirect");
        Intent expectedIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(expectedRedirectUri));
        expectedIntent.setPackage(activity.getPackageName());
        packageManager.addResolveInfoForIntent(expectedIntent, resolveInfo);

        new SsoDeeplink.Builder(activity)
                .clientId(CLIENT_ID)
                .scopes(GENERAL_SCOPES)
                .appProtocol(appProtocol)
                .build()
                .execute(FlowVersion.REDIRECT_TO_SDK);

        ArgumentCaptor<Intent> intentArgumentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentArgumentCaptor.capture());

        Uri uri = intentArgumentCaptor.getValue().getData();
        assertThat(uri.getQueryParameter("redirect_uri")).isEqualTo(expectedRedirectUri);
    }

    @Test(expected = IllegalStateException.class)
    public void execute_withBothAppsBelowMinDefaultFlowVersion_shouldFail() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_SUPPORTED)).thenReturn(false);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_SUPPORTED)).thenReturn(false);

        new SsoDeeplink.Builder(activity)
                .clientId(CLIENT_ID)
                .scopes(GENERAL_SCOPES)
                .build()
                .execute();
    }

    @Test(expected = IllegalStateException.class)
    public void execute_withRedirectToSdkFlowVersion_andBothAppsBelowMinRedirectToSdkVersion_shouldFail() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(false);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(false);

        new SsoDeeplink.Builder(activity)
                .clientId(CLIENT_ID)
                .scopes(GENERAL_SCOPES)
                .build()
                .execute(FlowVersion.REDIRECT_TO_SDK);
    }

    @Test(expected = IllegalStateException.class)
    public void execute_withRedirectToSdkFlowVersion_andCantResolveRedirectIntent_shouldFail() {
        when(appProtocol.isInstalled(activity, UBER, MIN_UBER_RIDES_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(true);
        when(appProtocol.isInstalled(activity, UBER_EATS, MIN_UBER_EATS_VERSION_REDIRECT_FLOW_SUPPORTED)).thenReturn(true);
        packageManager.removeResolveInfosForIntent(redirectIntent, activity.getPackageName());

        new SsoDeeplink.Builder(activity)
                .clientId(CLIENT_ID)
                .scopes(GENERAL_SCOPES)
                .build()
                .execute(FlowVersion.REDIRECT_TO_SDK);
    }

    private void enableSupport(FlowVersion flowVersion) {
        when(appProtocol.isInstalled(activity, UBER, flowVersion.getMinSupportedRidesVersion())).thenReturn(true);
        when(appProtocol.isInstalled(activity, UBER_EATS, flowVersion.getMinSupportedEatsVersion())).thenReturn(true);
    }
}
