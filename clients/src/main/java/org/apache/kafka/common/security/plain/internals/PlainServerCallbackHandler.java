/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kafka.common.security.plain.internals;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

public class PlainServerCallbackHandler implements AuthenticateCallbackHandler {

    private final Logger logger = LoggerFactory.getLogger(PlainServerCallbackHandler.class);

    @Override
    public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {
//        this.jaasConfigEntries = jaasConfigEntries;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        String username = null;
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) username = ((NameCallback) callback).getDefaultName();
            else if (callback instanceof PlainAuthenticateCallback) {
                PlainAuthenticateCallback plainCallback = (PlainAuthenticateCallback) callback;
                boolean authenticated = authenticate(username, plainCallback.password());
                plainCallback.authenticated(authenticated);
            } else throw new UnsupportedCallbackException(callback);
        }
    }

    protected boolean authenticate(String username, char[] password) throws IOException {
        logger.info("=======开始kafka订阅鉴权=======");
        if (username == null) {
            logger.info("username为空");
            return false;
        } else {
//            String expectedPassword = JaasContext.configEntryOption(jaasConfigEntries,
//                    JAAS_USER_PREFIX + username,
//                    PlainLoginModule.class.getName());
//            return expectedPassword != null && Utils.isEqualConstantTime(password, expectedPassword.toCharArray());
            String pwd = new String(password);
            Properties properties = new Properties();
            try (FileInputStream inputStream = new FileInputStream("/opt/bitnami/kafka/config/server.properties")) {
                properties.load(inputStream);
                String devUrl = (String) properties.get("url");
                String adminUsername = (String) properties.get("admin.username");
                if(username.startsWith(adminUsername)){//超级管理员直接放行
                    return true;
                }
                URL apiUrl = new URL(devUrl);
                logger.info("======开始调用kafka鉴权接口，打开链接======");
                HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
                connection.setRequestMethod("POST");
                // 添加请求参数
                String urlParameters = "userName=" + URLEncoder.encode(username, "UTF-8") + "&pwd=" + URLEncoder.encode(pwd, "UTF-8");
                connection.setDoOutput(true);
                try (DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream())) {
                    outputStream.writeBytes(urlParameters);
                    outputStream.flush();
                }

                int responseCode = connection.getResponseCode();
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    String responseData = getResponseData(connection);
                    boolean isAuthenticated = Boolean.parseBoolean(responseData);
                    if (isAuthenticated) {
                        logger.info("======鉴权成功！======");
                        return true;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        logger.info("======鉴权失败！======");
        return false;
    }

    private static String getResponseData(HttpURLConnection connection) throws IOException {
        StringBuilder response = new StringBuilder();
        try (InputStreamReader inputStreamReader = new InputStreamReader(connection.getInputStream(), Charset.defaultCharset());
             BufferedReader in = new BufferedReader(inputStreamReader)) {
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
        }
        String responseData = response.toString();
        return responseData;
    }

    @Override
    public void close() throws KafkaException {
    }

}
