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

    public void onCancel(DialogInterface dialog) {
    }

    public void onClick(DialogInterface dialog, int which) {
    }

    public void onDismiss(DialogInterface dialog) {
    }
}
