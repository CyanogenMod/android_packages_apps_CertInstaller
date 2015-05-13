package com.android.certinstaller;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Resources;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.security.Credentials;
import android.security.KeyStore;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;

public class WiFiInstaller extends Activity {

    private static final String TAG = "WifiInstaller";
    private static final String NETWORK_NAME = "network_name";
    private static final String INSTALL_STATE = "install_state";
    WifiConfiguration mWifiConfiguration;
    WifiManager mWifiManager;
    boolean doNotInstall;

    @Override
    protected void onCreate(Bundle savedStates) {
        super.onCreate(savedStates);

        Bundle bundle = getIntent().getExtras();
        String uriString = bundle.getString(CertInstallerMain.WIFI_CONFIG_FILE);
        String mimeType = bundle.getString(CertInstallerMain.WIFI_CONFIG);
        byte[] data = bundle.getByteArray(CertInstallerMain.WIFI_CONFIG_DATA);

        Log.d(TAG, "WiFi data for " + CertInstallerMain.WIFI_CONFIG + ": " +
                mimeType + " is " + (data != null ? data.length : "-"));

        mWifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        mWifiConfiguration = mWifiManager.buildWifiConfig(uriString, mimeType, data);

        if (mWifiConfiguration != null) {
            WifiEnterpriseConfig enterpriseConfig = mWifiConfiguration.enterpriseConfig;
            doNotInstall = (enterpriseConfig.getEapMethod() == WifiEnterpriseConfig.Eap.TTLS
                    || enterpriseConfig.getEapMethod() == WifiEnterpriseConfig.Eap.TLS)
                    && enterpriseConfig.getCaCertificate() == null;
            if (!doNotInstall && (enterpriseConfig.getClientCertificate() != null
                    || enterpriseConfig.getCaCertificate() != null)) {
                if (!KeyStore.getInstance().isUnlocked()) {
                    try {
                        startActivity(new Intent(Credentials.UNLOCK_ACTION));
                    } catch (ActivityNotFoundException e) {
                        Log.w(TAG, e);
                    }
                }
            }
        } else {
            doNotInstall = true;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        createMainDialog();
    }

    private void createMainDialog() {
        Resources res = getResources();
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View layout = getLayoutInflater().inflate(R.layout.wifi_main_dialog, null);
        builder.setView(layout);

        TextView text = (TextView) layout.findViewById(R.id.wifi_info);
        if (!doNotInstall) {
            text.setText(String.format(getResources().getString(R.string.wifi_installer_detail),
                    mWifiConfiguration.providerFriendlyName));

            builder.setTitle(mWifiConfiguration.providerFriendlyName);
            builder.setIcon(res.getDrawable(R.drawable.signal_wifi_4_bar_lock_black_24dp));

            builder.setPositiveButton(R.string.wifi_install_label,
                    new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    if(mWifiManager.addNetwork(mWifiConfiguration) != -1
                            && mWifiManager.saveConfiguration()) {
                        Intent intent = new Intent(getApplicationContext(),
                                CredentialsInstallDialog.class);
                        intent.putExtra(NETWORK_NAME, mWifiConfiguration.providerFriendlyName);
                        intent.putExtra(INSTALL_STATE, 1);
                        startActivity(intent);
                    } else {
                        Intent intent = new Intent(getApplicationContext(),
                                CredentialsInstallDialog.class);
                        intent.putExtra(INSTALL_STATE, 0);
                        startActivity(intent);
                    }
                    dialog.dismiss();
                    finish();
                }
            });

            builder.setNegativeButton(R.string.wifi_cancel_label, new
                    DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                    finish();
                }
            });
        } else {
            text.setText(getResources().getString(R.string.wifi_installer_download_error));
            builder.setPositiveButton(R.string.done_label, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                    finish();
                }
            });
        }
        builder.create().show();
    }
}
