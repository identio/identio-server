import { AuthenticationData } from './authentication-data';

export class UsernamePasswordAuthenticationData implements AuthenticationData {
    method: string;
    username: string;
    password: string;

    constructor(method: string, username: string, password: string) {
        this.method = method;
        this.username = username;
        this.password = password;
    }
}