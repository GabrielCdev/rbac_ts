import { AccessControl } from 'accesscontrol'

const ac = new AccessControl();

export function roles() {
    ac.grant('operador').readOwn('profile').updateOwn('profile');

    ac.grant('supervisor').extend('operador').readAny('profile');

    ac.grant('admin').extend('operador').extend('supervisor').updateAny('profile').deleteAny('profile');

    return ac;
}