/*
 * Copyright (c) 2021 - for information on the respective copyright owner
 * see the NOTICE file and/or the repository https://github.com/carbynestack/cli.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package io.carbynestack.cli.client.castor.command;

import io.carbynestack.castor.client.download.CastorIntraVcpClient;
import io.carbynestack.castor.client.download.DefaultCastorIntraVcpClient;
import io.carbynestack.castor.client.upload.CastorUploadClient;
import io.carbynestack.castor.client.upload.DefaultCastorUploadClient;
import io.carbynestack.castor.common.CastorServiceInfo;
import io.carbynestack.cli.CsClientCliCommandRunner;
import io.carbynestack.cli.client.castor.CastorClientCli;
import io.carbynestack.cli.client.castor.config.CastorClientCliCommandConfig;
import io.carbynestack.cli.configuration.Configuration;
import io.carbynestack.cli.configuration.VcpConfiguration;
import io.carbynestack.cli.exceptions.CsCliConfigurationException;
import io.carbynestack.cli.exceptions.CsCliRunnerException;
import io.carbynestack.cli.login.CsCliLoginException;
import io.carbynestack.cli.login.VcpToken;
import io.carbynestack.cli.login.VcpTokenStore;
import io.carbynestack.cli.util.KeyStoreUtil;
import io.vavr.control.Option;
import io.vavr.control.Try;
import lombok.extern.slf4j.Slf4j;

@Slf4j
abstract class CastorClientCliCommandRunner<T extends CastorClientCliCommandConfig>
    extends CsClientCliCommandRunner<T> {
  static final long CASTOR_COMMUNICATION_TIMEOUT = 10000L;

  CastorUploadClient castorUploadClient;
  CastorIntraVcpClient castorIntraVcpClient;

  CastorClientCliCommandRunner(T config)
      throws CsCliRunnerException, CsCliConfigurationException, CsCliLoginException {
    super(config);
    initializeMessageBundle(CastorClientCli.CASTOR_MESSAGE_BUNDLE);
    Configuration configuration = Configuration.getInstance();
    VcpConfiguration vcpConfiguration = configuration.getProvider(config.getId());
    Option<VcpToken> token = getVcpToken(vcpConfiguration);
    castorUploadClient =
        config
            .getCustomUploadClientFactory()
            .map(factory -> Try.of(factory::create))
            .getOrElse(
                Try.of(
                    () -> {
                        String[] addressPort = vcpConfiguration.getCastorServiceUri().getGrpcServiceUri().split(":");
                        String address = addressPort[0];
                        String port = addressPort[1];
                      DefaultCastorUploadClient.Builder builder =
                          DefaultCastorUploadClient.builder(
                              address,
                                  port);
                      if(configuration.isNoSslValidation())
                        return builder.build();
                      else
                          return builder.withCertificate(configuration.getCertificateFilePath()).build();
                    }))
            .getOrElseThrow(
                exception ->
                    new CsCliRunnerException(
                        getMessages().getString("client-instantiation-failed"), exception));
    castorIntraVcpClient =
        config
            .getCustomIntraVcpClientFactory()
            .map(factory -> Try.of(factory::create))
            .getOrElse(
                Try.of(
                    () -> {
                        CastorServiceInfo castorServiceInfo = vcpConfiguration.getCastorServiceUri();
                        castorServiceInfo.addCertificate(configuration.getCertificateFilePath());
                      DefaultCastorIntraVcpClient.Builder intraVcpClientBuilder =
                          DefaultCastorIntraVcpClient.builder(castorServiceInfo);
                      KeyStoreUtil.tempKeyStoreForPems(configuration.getTrustedCertificates())
                          .peek(intraVcpClientBuilder::withTrustedCertificate);
                      if (configuration.isNoSslValidation()) {
                        intraVcpClientBuilder.withoutSslCertificateValidation();
                      }
                      else{
                          intraVcpClientBuilder.withTrustedCertificate(castorServiceInfo.getCertificatePath());
                      }
//                      token
//                          .map(
//                              t ->
//                                  BearerTokenProvider.builder()
//                                      .bearerToken(
//                                          vcpConfiguration.getCastorServiceUri(),
//                                          t.getAccessToken())
//                                      .build())
//                          .peek(intraVcpClientBuilder::withBearerTokenProvider);
                      return intraVcpClientBuilder.build();
                    }))
            .getOrElseThrow(
                exception ->
                    new CsCliRunnerException(
                        getMessages().getString("client-instantiation-failed"), exception));
  }

  private Option<VcpToken> getVcpToken(VcpConfiguration vcpConfiguration)
      throws CsCliLoginException, CsCliRunnerException {
    if (!VcpTokenStore.exists()) {
      return Option.none();
    } else {
      VcpTokenStore vcpTokenStore =
          VcpTokenStore.load(true).getOrElseThrow(CsCliLoginException::new);
      return Option.some(
          vcpTokenStore.getTokens().stream()
              .filter(t -> t.getVcpBaseUrl().equals(vcpConfiguration.getBaseUrl().toString()))
              .findFirst()
              .orElseThrow(
                  () -> new CsCliRunnerException("No matching OAuth2 access token found", null)));
    }
  }
}
