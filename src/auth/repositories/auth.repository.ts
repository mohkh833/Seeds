import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { HttpStatus } from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/CreateUserDto';
import { UserService } from 'src/user/user.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from '../dto/auth.dto';
import { generateRandomToken } from '../utils';
import { ResetPasswordDto } from 'src/auth/dto/resetPassword.dto';
import { EmailService } from 'src/email/email.service';
import { VerifyEmailDto } from '../dto/verifyEmail.dto';
@Injectable()
export class AuthRepository {
	constructor(
		private usersService: UserService,
		private jwtService: JwtService,
		private emailService: EmailService
	) {}

	async signUp(createUserDto: CreateUserDto, isOAuthVerified?: boolean) {
		try {
			// check if user exists
			const userExists = await this.usersService.findByUserName(createUserDto.username);

			if (userExists) throw new BadRequestException('User already exists');

			const emailExists = await this.usersService.findByEmail(createUserDto.email);

			if (emailExists) throw new BadRequestException('Email already exists');

			// Hash Password
			const hash = await this.hashData(createUserDto.password);
			const newUser = await this.usersService.createUser({
				...createUserDto,
				password: hash
			});

			// if signed up using any Oauth platforms without verifying by email
			if (isOAuthVerified) {
				await this.usersService.update(newUser.id, { isVerified: true });

				const tokens = await this.getTokens(newUser.id, newUser.username);
				await this.updateRefreshToken(newUser.id, tokens.refreshToken);

				return { status: HttpStatus.OK, data: [ tokens ], message: 'User signed up successfully' };
			}

			this.sendEmail(newUser.email,'verify','https://example.com/verify?=','Verification email');

			return {
				status: HttpStatus.CREATED,
				message: 'A verification email is sent to you please verify your account '
			};
		} catch (e) {
			return { status: e.status, message: e.message || 'my error' };
		}
	}

	async verifyEmail(verifyEmailDto: VerifyEmailDto) {
		try {
			const { email, verifyToken } = verifyEmailDto;

			const user = await this.usersService.findByEmail(email);

			if (verifyToken != user.verifyToken) {
				throw new BadRequestException('verifyToken is not correct');
			}

			await this.usersService.update(user.id, { isVerified: true });

			const tokens = await this.getTokens(user.id, user.username);
			await this.updateRefreshToken(user.id, tokens.refreshToken);

			return { status: HttpStatus.OK, data: [ tokens ], message: 'User verified successfully' };
		} catch (err) {
			return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: err.message || 'my error' };
		}
	}

	async signIn(data: AuthDto) {
		try {
			const user = await this.usersService.findByUserName(data.username);

			if (!user) throw new BadRequestException('User does not exist ');

			const passwordMatches = await argon2.verify(user.password, data.password);

			if (!passwordMatches) throw new BadRequestException('Password is incorrect');

			if (!user.isVerified) throw new BadRequestException('user is not verified');

			const tokens = await this.getTokens(user.id, user.username);

			await this.updateRefreshToken(user.id, tokens.refreshToken);

			return { status: HttpStatus.OK, data: [ tokens ], message: 'User signed in successfully' };
		} catch (e) {
			return { status: e.status, message: e.message || 'my error' };
		}
	}

	async logOut(userId: number) {
		return this.usersService.update(userId, { refreshToken: '' });
	}

	hashData(data: string) {
		return argon2.hash(data);
	}

	async updateRefreshToken(userId: number, refreshToken: string) {
		const hashedRefreshToken = await this.hashData(refreshToken);
		try {
			await this.usersService.update(userId, {
				refreshToken: hashedRefreshToken
			});
		} catch (e) {
			return e;
		}
	}

	async getTokens(userId: number, username: string) {
		const [ accessToken, refreshToken ] = await Promise.all([
			this.jwtService.signAsync(
				{
					sub: userId,
					username
				},
				{
					secret: process.env.JWT_ACCESS_SECRET,
					expiresIn: '15m'
				}
			),
			this.jwtService.signAsync(
				{
					sub: userId,
					username
				},
				{
					secret: process.env.JWT_REFRESH_SECRET,
					expiresIn: '7d'
				}
			)
		]);

		return {
			accessToken,
			refreshToken
		};
	}

	async refreshTokens(userId: number, refreshToken: string) {
		try {
			const user = await this.usersService.findById(userId);
			if (!user || !user.refreshToken) throw new ForbiddenException('Access Denied');

			const refreshTokenMatches = await argon2.verify(user.refreshToken, refreshToken);

			if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

			const tokens = await this.getTokens(user.id, user.username);

			await this.updateRefreshToken(user.id, tokens.refreshToken);

			return { status: HttpStatus.OK, data: [ tokens ], message: 'refresh token is refreshed successfully' };
		} catch (e) {
			return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: e.message || 'my error' };
		}
	}

	async sendEmail(email: string, tokenType: string, tokenLink: string, subject: string): Promise<object> {
		try {
			const user = await this.usersService.findByEmail(email);
			if (!user) throw new BadRequestException('Email Not Exists');

			const token = generateRandomToken(); // Generate a secure random token
			const tokenExpiry = new Date(Date.now() + 3600000); // Token expires in 1 hour

			if (tokenType === 'reset') {
				await this.usersService.update(user.id, { resetToken: token, resetTokenExpiry: tokenExpiry });
			} else if (tokenType === 'verify') {
				await this.usersService.update(user.id, { verifyToken: token });
			}

			// Send the email with the token link
			const text = `Click the following link to ${tokenType} your ${tokenType === 'reset'
				? 'password'
				: 'account'}: ${tokenLink}${token}`;

			await this.emailService.sendMail({ to: email, subject, text });

			return { status: HttpStatus.OK, message: `A ${tokenType} email is sent successfully` };
		} catch (e) {
			return { status: e.status, message: e.message || 'my error' };
		}
	}

	// async sendPasswordResetToken(email: string): Promise<object> {
	// 	try {
	// 		const user = await this.usersService.findByEmail(email);

	// 		if (!user) throw new BadRequestException('Email Not Exists');

	// 		const resetToken = generateRandomToken(); // Generate a secure random token

	// 		const resetTokenExpiry = new Date(Date.now() + 3600000); // Token expires in 1 hour
	// 		await this.usersService.update(user.id, { resetToken, resetTokenExpiry });

	// 		//Send the reset token to user through email

	// 		const subject = 'Password Reset';

	// 		const text = `Click the following link to reset your password: https://example.com/reset?token=${resetToken}`;

	// 		await this.emailService.sendMail({ to: email, subject, text });

	// 		return { status: HttpStatus.OK, message: 'Reset Token is sent successfully' };
	// 	} catch (e) {
	// 		return { status: e.status, message: e.message || 'my error' };
	// 	}
	// }

	// async sendVerifyEmail(email: string) {
	// 	try {
	// 		const user = await this.usersService.findByEmail(email);

	// 		if (!user) throw new BadRequestException('Email Not Exists');

	// 		const verifyToken = generateRandomToken(); // Generate a secure random token

	// 		await this.usersService.update(user.id, { verifyToken });

	// 		//Send the verify token to user through email

	// 		const subject = 'Verification mail';

	// 		const text = `Click the following link to verify your account : https://example.com/verify?token=${verifyToken}`;

	// 		await this.emailService.sendMail({ to: email, subject, text });

	// 		return {
	// 			status: HttpStatus.OK,
	// 			message: 'A verification email is resent to you please verify your account '
	// 		};
	// 	} catch (err) {
	// 		return { status: err.status, message: err.message || 'my error' };
	// 	}
	// }

	async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<object> {
		try {
			const { email, password, resetToken } = resetPasswordDto;

			const user = await this.usersService.findByEmail(email);

			if (!user) throw new BadRequestException('Email is not exists');

			if (user.resetToken !== resetToken || user.resetTokenExpiry < new Date()) {
				throw new BadRequestException('Token is not valid');
			}

			const hash = await this.hashData(password); // Hash Password

			this.usersService.update(user.id, { password: hash, resetToken: null, resetTokenExpiry: null }); // update password
			// response
			return { status: HttpStatus.OK, message: 'Password Reset Successfully' };
		} catch (e) {
			return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: e.message || 'my error' };
		}
	}

	async googleSignIn(user: any) {
		try {
			if (!user) {
				throw new BadRequestException('Unauthenticated');
			}

			const userExists = await this.usersService.findByEmail(user.email);

			if (!userExists) {
				return this.signUp(user, true);
			}

			const tokens = await this.getTokens(userExists.id, userExists.username);

			await this.updateRefreshToken(userExists.id, tokens.refreshToken);

			return { status: HttpStatus.OK, data: [ tokens ], message: 'User signed in successfully' };
		} catch (err) {
			return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: err.message || 'my error' };
		}
	}
}
