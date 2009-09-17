/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.certinstaller;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.security.CertTool;
import android.security.Keystore;
import android.text.Html;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * The app that installs certificates to keystore. It reacts to two intents:
 * {@link CertTool#ACTION_ADD_CREDENTIAL} and
 * {@link CertTool#ACTION_INSTALL_CERT_FROM_SDCARD}.
 */
public class CertInstaller extends Activity
            implements DialogInterface.OnClickListener,
            DialogInterface.OnDismissListener,
            DialogInterface.OnCancelListener {
    private static final int CSTOR_NAME_CREDENTIAL_DIALOG = 1;
    private static final int REQUEST_UNLOCK_CODE = 1;
    private static final String TAG = "CERT_INSTALL";

    private Keystore mKeystore = Keystore.getInstance();
    private View mView;
    private boolean mConfirm = true;

    private CstorAddCredentialHelper mCstorAddCredentialHelper;
    private File mCertFile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        handleIntents(getIntent());
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        deleteCert(mCertFile);
    }

    @Override
    protected Dialog onCreateDialog (int id) {
        switch (id) {
            case CSTOR_NAME_CREDENTIAL_DIALOG:
                return createNameCredentialDialog();

            default:
                return null;
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode != REQUEST_UNLOCK_CODE) {
            Log.e("CERT_INSTALL", "unknown request code: " + requestCode);
            return;
        }

        if (isCstorUnlocked()) {
            addCredentialAndFinish();
        } else {
            toastErrorAndFinish(R.string.cert_not_saved);
        }
    }

    private void handleIntents(Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();

        if (CertTool.ACTION_ADD_CREDENTIAL.equals(action)) {
            Log.d(TAG, "add credential");
            mCstorAddCredentialHelper = new CstorAddCredentialHelper(intent);
            showDialog(CSTOR_NAME_CREDENTIAL_DIALOG);
        } else if (CertTool.ACTION_INSTALL_CERT_FROM_SDCARD.equals(action)) {
            Log.d(TAG, "install cert from sdcard");
            installCertFromSdCard();
        } else {
            Log.d(TAG, "unsupported action: " + action);
            finish();
        }
    }

    private Dialog createNameCredentialDialog() {
        mView = View.inflate(this, R.layout.name_credential_dialog_view, null);

        hideError();
        if (!mCstorAddCredentialHelper.isPkcs12Keystore()) {
            hide(R.id.credential_password_container);
        }

        setViewText(R.id.credential_name_title, R.string.credential_name);
        setViewText(R.id.credential_info_title, R.string.credential_info);
        setViewText(R.id.credential_info,
                mCstorAddCredentialHelper.getDescription().toString());

        Dialog d = new AlertDialog.Builder(this)
                .setView(mView)
                .setTitle(R.string.name_credential_dialog_title)
                .setPositiveButton(android.R.string.ok, this)
                .setNegativeButton(android.R.string.cancel, this)
                .setOnCancelListener(this)
                .create();
        d.setOnDismissListener(this);
        return d;
    }

    private File getCertFile() {
        return new File(Environment.getExternalStorageDirectory(), "certs.p12");
    }

    private void toastErrorAndFinish(int msgId) {
        Toast.makeText(this, msgId, Toast.LENGTH_LONG).show();
        mCertFile = null; // so that the file is not deleted in onDestroy()
        finish();
    }

    private void installCertFromSdCard() {
        File f = mCertFile = getCertFile();
        if (f.exists()) {
            long length = f.length();
            if (length < 1000000) {
                byte[] data = readCert(f);
                if (data == null) {
                    toastErrorAndFinish(R.string.cert_read_error);
                    return;
                }
                handleIntents(new CertTool.AddCredentialIntentBuilder(
                        CertTool.TITLE_PKCS12_KEYSTORE,
                        getString(R.string.p12_description))
                        .addCredential(CertTool.USER_KEY, data)
                        .build());
            } else {
                Log.d(TAG, "cert file is too large: " + length);
                toastErrorAndFinish(R.string.cert_too_large_error);
            }
        } else {
            Log.d(TAG, "cert file does not exist");
            toastErrorAndFinish(R.string.cert_missing_error);
        }
    }

    private byte[] readCert(File f) {
        try {
            byte[] data = new byte[(int) f.length()];
            FileInputStream fis = new FileInputStream(f);
            fis.read(data);
            fis.close();
            return data;
        } catch (IOException e) {
            Log.d(TAG, "cert file read error: " + e);
            return null;
        }
    }

    private void deleteCert(File f) {
        if ((f != null) && !f.delete()) {
            Log.d(TAG, "cannot delete cert: " + f);
        }
    }

    private boolean isCstorUnlocked() {
        return (mKeystore.getState() == Keystore.UNLOCKED);
    }

    private boolean addCredential() {
        Log.d(TAG, "add credential");
        if (mCstorAddCredentialHelper.saveToStorage() != 0) {
            if (mCstorAddCredentialHelper.isPkcs12Keystore()) {
                showError(R.string.password_error);
            } else {
                showError(R.string.storage_error);
            }
            Log.d(TAG, "failed to add credential");
            return false;
        }
        Log.d(TAG, "credential is added: "
                + mCstorAddCredentialHelper.getName());
        String message = String.format(getString(R.string.cert_is_added),
                mCstorAddCredentialHelper.getName());
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        return true;
    }

    // provided credential storage is enabled
    private void addCredentialAndFinish() {
        if (addCredential()) {
            finish();
        } else {
            // some error occurs
            showDialog(CSTOR_NAME_CREDENTIAL_DIALOG);
        }
    }

    public void onCancel(DialogInterface dialog) {
        if (mCstorAddCredentialHelper == null) return;

        mCstorAddCredentialHelper = null; // so onDismiss() can tell
        toastErrorAndFinish(R.string.cert_not_saved);
    }

    public void onClick(DialogInterface dialog, int which) {
        if (which == DialogInterface.BUTTON_NEGATIVE) {
            onCancel(dialog);
            return;
        }

        mConfirm = validateForm();
    }

    // dialog can only re-opened in onDismiss()
    public void onDismiss(DialogInterface dialog) {
        if (!mConfirm) {
            mConfirm = true;
            // validation error
            showDialog(CSTOR_NAME_CREDENTIAL_DIALOG);
        } else {
            // real action: helper is null if user cancelled the dialog
            if (mCstorAddCredentialHelper != null) {
                if (isCstorUnlocked()) {
                    addCredentialAndFinish();
                } else {
                    startActivityForResult(new Intent(
                            Keystore.ACTION_UNLOCK_CREDENTIAL_STORAGE),
                            REQUEST_UNLOCK_CODE);
                }
            }
        }
    }

    private boolean validateForm() {
        hideError();

        String name = getViewText(R.id.credential_name);
        if (TextUtils.isEmpty(name)) {
            showError(R.string.name_empty_error);
            return false;
        }

        for (int i = 0, len = name.length(); i < len; i++) {
            if (!Character.isLetterOrDigit(name.charAt(i))) {
                showError(R.string.name_char_error);
                return false;
            }
        }

        mCstorAddCredentialHelper.setName(name);

        if (mCstorAddCredentialHelper.isPkcs12Keystore()) {
            String password = getViewText(R.id.credential_password);
            if (TextUtils.isEmpty(password)) {
                showError(R.string.password_empty_error);
                return false;
            }

            mCstorAddCredentialHelper.setPassword(password);
        }

        return true;
    }

    private TextView showError(int messageId) {
        TextView v = (TextView) mView.findViewById(R.id.error);
        v.setText(messageId);
        if (v != null) v.setVisibility(View.VISIBLE);
        return v;
    }

    private void hide(int viewId) {
        View v = mView.findViewById(viewId);
        if (v != null) v.setVisibility(View.GONE);
    }

    private void hideError() {
        hide(R.id.error);
    }

    private String getViewText(int viewId) {
        return ((TextView) mView.findViewById(viewId)).getText().toString();
    }

    private void setViewText(int viewId, String text) {
        TextView v = (TextView) mView.findViewById(viewId);
        if (v != null) v.setText(text);
    }

    private void setViewText(int viewId, int textId) {
        TextView v = (TextView) mView.findViewById(viewId);
        if (v != null) v.setText(textId);
    }

    private class CstorAddCredentialHelper {
        CertTool.AddCredentialRequest mRequest;
        private String mDescription;
        private String mName;
        private String mPassword;

        CstorAddCredentialHelper(Intent intent) {
            mRequest = new CertTool.AddCredentialRequest(intent);
        }

        boolean isPkcs12Keystore() {
            return CertTool.TITLE_PKCS12_KEYSTORE.equals(mRequest.getTitle());
        }

        CharSequence getDescription() {
            if (mDescription == null) {
                // build description string
                StringBuilder sb = new StringBuilder();
                for (String s : mRequest.getDescriptions()) {
                    sb.append(s).append("<br>");
                }
                mDescription = sb.toString();
            }
            return Html.fromHtml(mDescription);
        }

        void setName(String name) {
            mName = name;
        }

        String getName() {
            return mName;
        }

        void setPassword(String password) {
            mPassword = password;
        }

        int saveToStorage() {
            if (isPkcs12Keystore()) {
                return CertTool.getInstance().addPkcs12Keystore(
                        mRequest.getDataAt(0), mPassword, mName);
            } else {
                Keystore ks = Keystore.getInstance();
                for (int i = 0; ; i++) {
                    byte[] blob = mRequest.getDataAt(i);
                    if (blob == null) break;
                    int ret = ks.put(mRequest.getNamespaceAt(i), mName,
                            new String(blob));
                    if (ret != 0) return ret;
                }
            }
            return 0;
        }
    }
}
