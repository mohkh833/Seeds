import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth2';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
	constructor() {
		super({
			clientID: process.env.CLIENT_ID,
			clientSecret: process.env.CLIENT_SECRET,
			callbackURL: process.env.CALLBACK_URL,
			scope: [ 'email', 'profile' ]
		});
	}

	async validate(_accessToken: string, _refreshToken: string, profile: any, done: VerifyCallback): Promise<any> {
		const { id, name, emails } = profile;
		const username = emails[0].value.split('@')[0] + '_' + Math.floor(Math.random() * 1000);
        const password = this.generatePassword(username)
		const user = {
			provider: 'google',
			id: id,
			email: emails[0].value,
			name: `${name.givenName} ${name.familyName}`,
			// picture: photos[0].value,
			username: username,
			password: password
		};

		done(null, user);
	}

	generatePassword(username: string) {
		const maxLength = 16;
		const minLength = 10;
		const passwordChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+';

		let password = username + Math.random().toString(36).substring(2, 6);
		while (password.length < maxLength) {
			password += passwordChars[Math.floor(Math.random() * passwordChars.length)];
		}

		if (password.length > maxLength) {
			password = password.substr(0, maxLength);
		} else if (password.length < minLength) {
			const diff = minLength - password.length;
			password = password.substr(0, maxLength - diff);
			while (password.length < minLength) {
				password += passwordChars[Math.floor(Math.random() * passwordChars.length)];
			}
		}

		return password;
	}
}
