import { ViewModel } from "shared_types/types/shared_types";

import { CredentialViewModel } from './credential';
import { IssuanceViewModel } from './issuance';
import { PresentationViewModel } from './presentation';

export type LocalViewModel = {
    credential: CredentialViewModel,
    issuance: IssuanceViewModel,
    presentation: PresentationViewModel,
    error?: string,
    view: string,
};

export const localView = (vm: ViewModel): LocalViewModel => {
    const credential: CredentialViewModel = {
        credentials: JSON.parse(vm.credential.credentials),
    };

    const issuance: IssuanceViewModel = {
        issuer: vm.issuance.issuer,
        offered: JSON.parse(vm.issuance.offered),
        status: vm.issuance.status,
    };

    const presentation: PresentationViewModel = {
        credentials: JSON.parse(vm.presentation.credentials),
        status: vm.presentation.status,
    };

    return {
        credential,
        issuance,
        presentation,
        error: vm.error || undefined,
        view: vm.view,
    };
};
