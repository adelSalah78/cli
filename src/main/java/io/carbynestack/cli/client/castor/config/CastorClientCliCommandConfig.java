/*
 * Copyright (c) 2021 - for information on the respective copyright owner
 * see the NOTICE file and/or the repository https://github.com/carbynestack/cli.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package io.carbynestack.cli.client.castor.config;

import static io.carbynestack.cli.client.castor.CastorClientCli.CASTOR_MESSAGE_BUNDLE;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import io.carbynestack.cli.client.castor.CastorIntraVcpClientFactory;
import io.carbynestack.cli.config.CsClientCliCommandConfig;
import io.vavr.control.Option;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
@Parameters(resourceBundle = CASTOR_MESSAGE_BUNDLE)
public abstract class CastorClientCliCommandConfig extends CsClientCliCommandConfig {
  private final Option<CastorIntraVcpClientFactory> customIntraVcpClientFactory;

  @Parameter(descriptionKey = "option.service-id-description", required = true)
  private String id;

  public int getId() {
    return Integer.parseInt(id);
  }
}
