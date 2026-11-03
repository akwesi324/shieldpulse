package com.maskedops.securitylabs;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Security Labs mobile: a WebView showing the bundled UI (assets/), plus a native HTTPS client.
 *
 * Security model:
 *  - The WebView only loads the app's own assets; any other link opens in the browser.
 *  - All network traffic goes through LabBridge.request(), which pins the console's certificate
 *    by SHA-256 fingerprint. The only unpinned request is the pairing probe, which reads the
 *    fingerprint so you can compare it with the PC screen; nothing secret is sent on it.
 *  - Pairing token and pin are stored in this app's private SharedPreferences.
 */
public class MainActivity extends Activity {
    private static final String START_URL = "file:///android_asset/index.html";
    private WebView webView;
    private final ExecutorService pool = Executors.newFixedThreadPool(2);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(Color.parseColor("#0F1115"));
        getWindow().setNavigationBarColor(Color.parseColor("#0F1115"));

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#0F1115"));
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowContentAccess(false);
        s.setAllowFileAccess(true); // needed for file:///android_asset only
        s.setAllowFileAccessFromFileURLs(false);
        s.setAllowUniversalAccessFromFileURLs(false);
        s.setGeolocationEnabled(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (uri.toString().startsWith("file:///android_asset/")) return false;
                try { startActivity(new Intent(Intent.ACTION_VIEW, uri)); } catch (Exception ignored) { }
                return true;
            }
        });
        webView.addJavascriptInterface(new LabBridge(), "LabBridge");
        webView.loadUrl(START_URL);
        setContentView(webView);
    }

    @Override
    public void onBackPressed() {
        webView.evaluateJavascript("window.__labBack ? window.__labBack() : false", value -> {
            if (!"true".equals(value)) MainActivity.super.onBackPressed();
        });
    }

    @Override
    protected void onDestroy() {
        pool.shutdownNow();
        webView.destroy();
        super.onDestroy();
    }

    // -------------------------------------------------------------------------

    private static String sha256Hex(byte[] data) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Trusts exactly one certificate (by SHA-256), or, with no pin, records what it saw. */
    private static final class PinningTrustManager implements X509TrustManager {
        final String expected;
        String seen;
        PinningTrustManager(String expected) { this.expected = expected; }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("client certificates not used");
        }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("no certificate");
            try { seen = sha256Hex(chain[0].getEncoded()); } catch (Exception e) { throw new CertificateException(e); }
            if (expected != null && !expected.isEmpty() && !expected.equalsIgnoreCase(seen)) {
                throw new CertificateException("certificate mismatch");
            }
        }

        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    private final class LabBridge {
        private SharedPreferences prefs() { return getSharedPreferences("lab", Context.MODE_PRIVATE); }

        @JavascriptInterface public String getConfig() { return prefs().getString("config", ""); }
        @JavascriptInterface public void saveConfig(String json) { prefs().edit().putString("config", json).apply(); }
        @JavascriptInterface public void clearConfig() { prefs().edit().remove("config").apply(); }
        @JavascriptInterface public String deviceName() { return (Build.MANUFACTURER + " " + Build.MODEL).trim(); }
        @JavascriptInterface public String appVersion() { return BuildConfigInfo.VERSION; }

        /**
         * Async HTTPS request. Result is delivered to window.__labResolve(id, resultJson) with
         * { status, body, fingerprint, error, pinMismatch }.
         */
        @JavascriptInterface
        public void request(final int id, final String method, final String url, final String body,
                            final String bearer, final String pin) {
            pool.execute(() -> {
                JSONObject result = new JSONObject();
                PinningTrustManager tm = new PinningTrustManager(pin);
                HttpsURLConnection conn = null;
                try {
                    URL u = new URL(url);
                    if (!"https".equals(u.getProtocol())) throw new IllegalArgumentException("HTTPS only");
                    SSLContext ctx = SSLContext.getInstance("TLS");
                    ctx.init(null, new TrustManager[] { tm }, null);
                    conn = (HttpsURLConnection) u.openConnection();
                    conn.setSSLSocketFactory(ctx.getSocketFactory());
                    // Identity is proven by the pinned fingerprint, not the hostname (the PC is
                    // reached by its IP address, which a self-signed certificate cannot name).
                    conn.setHostnameVerifier((host, session) -> true);
                    conn.setConnectTimeout(6000);
                    conn.setReadTimeout(20000);
                    conn.setRequestMethod(method);
                    conn.setRequestProperty("Accept", "application/json");
                    if (bearer != null && !bearer.isEmpty()) conn.setRequestProperty("Authorization", "Bearer " + bearer);
                    if (body != null && !body.isEmpty()) {
                        conn.setDoOutput(true);
                        conn.setRequestProperty("Content-Type", "application/json");
                        try (OutputStream os = conn.getOutputStream()) { os.write(body.getBytes(StandardCharsets.UTF_8)); }
                    }
                    int status = conn.getResponseCode();
                    InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
                    result.put("status", status);
                    result.put("body", in == null ? "" : readAll(in));
                } catch (Exception e) {
                    boolean mismatch = tm.seen != null && pin != null && !pin.isEmpty() && !pin.equalsIgnoreCase(tm.seen);
                    try {
                        result.put("status", 0);
                        result.put("error", mismatch ? "certificate mismatch" : String.valueOf(e.getMessage()));
                        result.put("pinMismatch", mismatch);
                    } catch (Exception ignored) { }
                } finally {
                    if (conn != null) conn.disconnect();
                }
                try { if (tm.seen != null) result.put("fingerprint", tm.seen); } catch (Exception ignored) { }
                final String js = "window.__labResolve(" + id + "," + JSONObject.quote(result.toString()) + ")";
                webView.post(() -> webView.evaluateJavascript(js, null));
            });
        }
    }

    private static String readAll(InputStream in) throws Exception {
        try (InputStream is = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > 4 * 1024 * 1024) throw new IllegalStateException("response too large");
            }
            return out.toString("UTF-8");
        }
    }
}
