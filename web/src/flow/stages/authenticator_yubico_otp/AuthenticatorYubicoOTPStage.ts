import "#flow/FormStatic";
import "#flow/components/ak-flow-card";
import PFButton from "@patternfly/patternfly/components/Button/button.css";
import PFForm from "@patternfly/patternfly/components/Form/form.css";
import PFFormControl from "@patternfly/patternfly/components/FormControl/form-control.css";
import PFLogin from "@patternfly/patternfly/components/Login/login.css";
import PFTitle from "@patternfly/patternfly/components/Title/title.css";

import { SlottedTemplateResult } from "#elements/types";

import { AKFormErrors } from "#components/ak-field-errors";
import { AKLabel } from "#components/ak-label";

import { FlowUserDetails } from "#flow/FormStatic";
import { BaseStage } from "#flow/stages/base";

import {
    AuthenticatorYubicoOTPChallenge,
    AuthenticatorYubicoOTPChallengeResponseRequest,
} from "@goauthentik/api";

import { msg } from "@lit/localize";
import { CSSResult, html, nothing } from "lit";
import { customElement } from "lit/decorators.js";

/**
 * Registers a YubiKey slot that types Yubico OTPs. Touching the key types an OTP and
 * presses Enter, which submits the form.
 */
@customElement("ak-stage-authenticator-yubico-otp")
export class AuthenticatorYubicoOTPStage extends BaseStage<
    AuthenticatorYubicoOTPChallenge,
    AuthenticatorYubicoOTPChallengeResponseRequest
> {
    static styles: CSSResult[] = [PFLogin, PFForm, PFFormControl, PFTitle, PFButton];

    protected render(): SlottedTemplateResult {
        if (!this.challenge) {
            return nothing;
        }

        return html`<ak-flow-card .challenge=${this.challenge}>
            <form class="pf-c-form" @submit=${this.submitForm}>
                ${FlowUserDetails({ challenge: this.challenge })}
                <p>
                    ${msg("Insert your YubiKey and touch it to enter a one-time password.", {
                        id: "yubico-otp.setup.description",
                    })}
                </p>
                <div class="pf-c-form__group">
                    ${AKLabel(
                        { required: true, htmlFor: "yubico-otp-code-input" },
                        msg("Yubico OTP", { id: "yubico-otp.setup.code.label" }),
                    )}
                    <input
                        id="yubico-otp-code-input"
                        type="text"
                        name="code"
                        placeholder=${msg("Touch your YubiKey...", {
                            id: "yubico-otp.setup.code.placeholder",
                        })}
                        autocomplete="off"
                        autocapitalize="off"
                        class="pf-c-form-control pf-m-monospace"
                        spellcheck="false"
                        autofocus
                        required
                    />
                    ${AKFormErrors({ errors: this.challenge.responseErrors?.code })}
                </div>

                <fieldset class="ak-c-fieldset pf-c-form__group pf-m-action">
                    <legend class="sr-only">${msg("Form actions")}</legend>
                    <button
                        name="continue"
                        type="submit"
                        class="pf-c-button pf-m-primary pf-m-block"
                    >
                        ${msg("Continue")}
                    </button>
                </fieldset>
            </form>
        </ak-flow-card>`;
    }
}

export default AuthenticatorYubicoOTPStage;

declare global {
    interface HTMLElementTagNameMap {
        "ak-stage-authenticator-yubico-otp": AuthenticatorYubicoOTPStage;
    }
}
