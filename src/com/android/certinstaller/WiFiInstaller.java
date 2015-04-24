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

    @Override
    protected void onCreate(Bundle savedStates) {
        super.onCreate(savedStates);

        Bundle bundle = getIntent().getExtras();
        String uriString = bundle.getString(CertInstallerMain.WIFI_CONFIG_FILE);
        String mimeType = bundle.getString(CertInstallerMain.WIFI_CONFIG);
        byte[] data = bundle.getByteArray(CertInstallerMain.WIFI_CONFIG_DATA);

        Log.d(TAG, "WiFi data for " + CertInstallerMain.WIFI_CONFIG + ": " +
                mimeType + " is " + (data != null ? data.length : "-"));

        WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        WifiConfiguration wifiConfiguration = wifiManager.buildWifiConfig(uriString, mimeType, data);

        WifiEnterpriseConfig enterpriseConfig = wifiConfiguration.enterpriseConfig;
        if (enterpriseConfig.getClientCertificate() != null ||
                enterpriseConfig.getCaCertificate() != null) {
            if (!KeyStore.getInstance().isUnlocked()) {
                try {
                    startActivity(new Intent(Credentials.UNLOCK_ACTION));
                } catch (ActivityNotFoundException e) {
                    Log.w(TAG, e);
                }
            }
        }
        createMainDialog(wifiManager, wifiConfiguration);
    }

    private static String roamingConsortiumsToString(Collection<Long> ois) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (long oi : ois) {
            if (first) {
                first = false;
            } else {
                sb.append(", ");
            }
            if (Long.numberOfLeadingZeros(oi) > 40) {
                sb.append(String.format("%06x", oi));
            } else {
                sb.append(String.format("%010x", oi));
            }
        }
        return sb.toString();
    }

    private static String mapEAPMethod(WifiEnterpriseConfig config) {
        switch (config.getEapMethod()) {
            case WifiEnterpriseConfig.Eap.TTLS:
                return "TTLS+" + mapInnerMethod(config.getPhase2Method());
            case WifiEnterpriseConfig.Eap.TLS:
                return "TLS";
            case WifiEnterpriseConfig.Eap.SIM:
                return "SIM";
            case WifiEnterpriseConfig.Eap.AKA:
                return "AKA";
            case WifiEnterpriseConfig.Eap.AKA_PRIME:
                return "AKA'";
            default:
                return String.format("Unsupported method %d", config.getEapMethod());
        }
    }

    private static String mapInnerMethod(int id) {
        switch (id) {
            case WifiEnterpriseConfig.Phase2.NONE:
                return "none";
            case WifiEnterpriseConfig.Phase2.PAP:
                return "PAP";
            case WifiEnterpriseConfig.Phase2.MSCHAP:
                return "MS-CHAP";
            case WifiEnterpriseConfig.Phase2.MSCHAPV2:
                return "MS-CHAPv2";
            case WifiEnterpriseConfig.Phase2.GTC:
                return "GTC";
            default:
                return String.format("Unsupported inner method %d", id);
        }
    }

    private void createMainDialog(final WifiManager wifiManager, final WifiConfiguration config) {
        Resources res = getResources();
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View layout = getLayoutInflater().inflate(R.layout.wifi_main_dialog, null);
        builder.setView(layout);

        TextView text = (TextView) layout.findViewById(R.id.wifi_info);
        text.setText(String.format("WiFi configuration from %s (%s)",
                config.providerFriendlyName, config.FQDN));

        Button detailButton = (Button) layout.findViewById(R.id.wifi_detail);

        detailButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                createDetailDialog(config);
            }
        });

        builder.setTitle(res.getString(R.string.wifi_title));

        builder.setPositiveButton(R.string.wifi_install_label, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                Log.d("WFDL", "OK");
                wifiManager.addNetwork(config);
                wifiManager.saveConfiguration();
                dialog.dismiss();
                finish();
            }
        });

        builder.setNegativeButton(R.string.wifi_cancel_label, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                Log.d("WFDL", "Cancel");
                dialog.dismiss();
                finish();
            }
        });

        builder.create().show();
    }

    private void createDetailDialog(WifiConfiguration config) {
        Resources res = getResources();
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View layout = getLayoutInflater().inflate(R.layout.wifi_detail_dialog, null);
        layout.setHorizontalScrollBarEnabled(true);
        builder.setView(layout);

        TextView text = (TextView) layout.findViewById(R.id.wifi_detail_text);
        text.setText(getDetailedInfo(res, config));

        builder.setTitle(String.format(res.getString(R.string.wifi_detail_title),
                config.providerFriendlyName));

        builder.setPositiveButton(R.string.wifi_dismiss_label,
                new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                Log.d("WFDL", "detail dismiss");
                dialog.dismiss();
            }
        });

        builder.create().show();
    }

    private static String getDetailedInfo(Resources res, WifiConfiguration wifiConfiguration) {
        if (wifiConfiguration == null) {
            return res.getString(R.string.wifi_no_config);
        }

        StringBuilder details = new StringBuilder();
        WifiEnterpriseConfig enterpriseConfig = wifiConfiguration.enterpriseConfig;
        details.append(String.format(res.getString(R.string.wifi_config_text),
                wifiConfiguration.providerFriendlyName,
                wifiConfiguration.FQDN,
                roamingConsortiumsToString(wifiConfiguration.roamingConsortiumIds),
                enterpriseConfig.getRealm(),
                mapEAPMethod(enterpriseConfig)));

        switch (enterpriseConfig.getEapMethod()) {
            case WifiEnterpriseConfig.Eap.TTLS:
                details.append(String.format(res.getString(R.string.wifi_ttls_config_text), enterpriseConfig.getIdentity()));
                details.append("Password: ").append(enterpriseConfig.getPassword()).append('\n');   // !!!
                if (enterpriseConfig.getCaCertificate() != null) {
                    details.append(String.format(res.getString(R.string.wifi_trust_config_text), enterpriseConfig.getCaCertificate()));
                }
                break;
            case WifiEnterpriseConfig.Eap.TLS:
                PrivateKey key = enterpriseConfig.getClientPrivateKey();
                String keyInfo;
                if (key instanceof RSAPrivateKey) {
                    RSAPrivateKey rsaKey = (RSAPrivateKey) key;
                    int bits = rsaKey.getModulus().bitLength();
                    keyInfo = "RSA " + (((bits + 7) / 8)*8) + " bits";
                }
                else {
                    keyInfo = key.getAlgorithm();
                }
                details.append(String.format(res.getString(R.string.wifi_tls_config_text), enterpriseConfig.getClientCertificate(), keyInfo));
                if (enterpriseConfig.getCaCertificate() != null) {
                    details.append(String.format(res.getString(R.string.wifi_trust_config_text), enterpriseConfig.getCaCertificate()));
                }
                break;
            case WifiEnterpriseConfig.Eap.SIM:
            case WifiEnterpriseConfig.Eap.AKA:
            case WifiEnterpriseConfig.Eap.AKA_PRIME:
                details.append(String.format(res.getString(R.string.wifi_sim_config_text), enterpriseConfig.getPlmn()));
                break;
        }
        return details.toString();
    }

    @Override
    protected void onResume() {
        super.onResume();
    }

    @Override
    protected void onPause() {
        super.onPause();
    }

    @Override
    protected void onSaveInstanceState(Bundle outStates) {
        super.onSaveInstanceState(outStates);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        finish();
    }
}
