import "#components/ak-secret-text-input";
import "#components/ak-text-input";
import "#elements/forms/FormGroup";
import "#elements/forms/HorizontalFormElement";
import { aki } from "#common/api/client";

import { AKFlowSearch } from "#admin/common/ak-flow-search/AKFlowSearch";
import { BaseStageForm } from "#admin/stages/BaseStageForm";

import { AuthenticatorYubicoOTPStage, FlowDesignationEnum, StagesApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html, TemplateResult } from "lit";
import { customElement } from "lit/decorators.js";

const YUBICLOUD_API_URL = "https://api.yubico.com/wsapi/2.0/verify";

@customElement("ak-stage-authenticator-yubico-otp-form")
export class AuthenticatorYubicoOTPStageForm extends BaseStageForm<AuthenticatorYubicoOTPStage> {
    protected endpoints = {
        load: (stageUuid: string) =>
            aki(StagesApi).stagesAuthenticatorYubicoOtpRetrieve({ stageUuid }),
        create: (authenticatorYubicoOTPStageRequest: AuthenticatorYubicoOTPStage) =>
            aki(StagesApi).stagesAuthenticatorYubicoOtpCreate({
                authenticatorYubicoOTPStageRequest,
            }),
        update: (
            stageUuid: string,
            authenticatorYubicoOTPStageRequest: AuthenticatorYubicoOTPStage,
        ) =>
            aki(StagesApi).stagesAuthenticatorYubicoOtpUpdate({
                stageUuid,
                authenticatorYubicoOTPStageRequest,
            }),
    };

    protected override renderForm(): TemplateResult {
        return html` <span>
                ${msg(
                    "Stage used to register a YubiKey that types Yubico OTPs. OTPs are checked with a validation server such as YubiCloud. This stage should be used for configuration flows.",
                    { id: "yubico-otp.stage.description" },
                )}
            </span>
            <ak-text-input
                label=${msg("Stage Name", {
                    id: "stage.name.label",
                })}
                required
                name="name"
                value=${this.instance?.name || ""}
                placeholder=${msg("Type a name for this stage...", {
                    id: "stage.name.placeholder",
                })}
                ?autofocus=${!this.instance}
            ></ak-text-input>
            <ak-form-element-horizontal
                label=${msg("Authenticator type name")}
                ?required=${false}
                name="friendlyName"
            >
                <input
                    type="text"
                    value="${this.instance?.friendlyName ?? ""}"
                    class="pf-c-form-control"
                />
                <p class="pf-c-form__helper-text">
                    ${msg(
                        "Display name of this authenticator, used by users when they enroll an authenticator.",
                    )}
                </p>
            </ak-form-element-horizontal>
            <ak-form-group open label="${msg("Stage-specific settings")}">
                <div class="pf-c-form">
                    <ak-text-input
                        name="apiUrl"
                        label=${msg("Validation server URL", {
                            id: "yubico-otp.stage.api-url.label",
                        })}
                        input-hint="code"
                        required
                        value=${this.instance?.apiUrl ?? YUBICLOUD_API_URL}
                        help=${msg(
                            "Verify endpoint of a server speaking the Yubico OTP validation protocol 2.0. YubiCloud is used by default.",
                            { id: "yubico-otp.stage.api-url.description" },
                        )}
                    ></ak-text-input>
                    <ak-text-input
                        name="clientId"
                        label=${msg("Client ID", { id: "yubico-otp.stage.client-id.label" })}
                        input-hint="code"
                        required
                        value=${this.instance?.clientId ?? ""}
                        help=${msg(
                            "For YubiCloud, get a client ID and secret key from https://upgrade.yubico.com/getapikey/",
                            { id: "yubico-otp.stage.client-id.description" },
                        )}
                    ></ak-text-input>
                    <ak-secret-text-input
                        name="secretKey"
                        label=${msg("Secret key", { id: "yubico-otp.stage.secret-key.label" })}
                        input-hint="code"
                        ?required=${!this.instance}
                        ?revealed=${!this.instance}
                        help=${msg(
                            "Base64 encoded key used to sign requests to the validation server and check its responses.",
                            { id: "yubico-otp.stage.secret-key.description" },
                        )}
                    ></ak-secret-text-input>
                    <ak-form-element-horizontal
                        label=${msg("Configuration flow")}
                        name="configureFlow"
                    >
                        ${AKFlowSearch({
                            name: "configureFlow",
                            flowType: FlowDesignationEnum.StageConfiguration,
                            value: this.instance?.configureFlow,
                            blankable: true,
                        })}
                        <p class="pf-c-form__helper-text">
                            ${msg(
                                "Flow used by an authenticated user to configure this Stage. If empty, user will not be able to configure this stage.",
                            )}
                        </p>
                    </ak-form-element-horizontal>
                </div>
            </ak-form-group>`;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-stage-authenticator-yubico-otp-form": AuthenticatorYubicoOTPStageForm;
    }
}
