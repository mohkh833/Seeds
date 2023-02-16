import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { HttpStatus } from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/CreateUserDto';
import { UserService } from 'src/user/user.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from '../dto/auth.dto';
import { generateRandomToken }  from "../utils"
import {ResetPasswordDto} from 'src/auth/dto/resetPassword.dto'
import { EmailService } from 'src/email/email.service';
@Injectable()
export class AuthRepository  {
	constructor(private usersService: UserService, private jwtService: JwtService, private emailService: EmailService) {}

	async signUp(createUserDto: CreateUserDto){
		try{
			// check if user exists
			const userExists = await this.usersService.findByUserName(createUserDto.username);

			if (userExists) throw new BadRequestException('User already exists');
	
			// Hash Password
			const hash = await this.hashData(createUserDto.password);
			const newUser = await this.usersService.createUser({
				...createUserDto,
				password: hash
			});
	
			const tokens = await this.getTokens(newUser.id, newUser.username);
			await this.updateRefreshToken(newUser.id, tokens.refreshToken);
			return { status: HttpStatus.OK, data: [tokens] }
		} catch(e){
			return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: e.message || 'my error' } 
		}
	}

	async signIn(data: AuthDto) {
		const user = await this.usersService.findByUserName(data.username);

		if (!user) throw new BadRequestException('User does not exist ');

		const passwordMatches = await argon2.verify(user.password, data.password);

		if (!passwordMatches) throw new BadRequestException('Password is incorrect');

		const tokens = await this.getTokens(user.id, user.username);

		await this.updateRefreshToken(user.id, tokens.refreshToken);

		return { status: HttpStatus.OK, data: [tokens] }
	}

	async logOut(userId: number) {
		return this.usersService.update(userId, { refreshToken: '' });
	}

	hashData(data: string) {
		return argon2.hash(data);
	}

	async updateRefreshToken(userId: number, refreshToken: string) {
		const hashedRefreshToken = await this.hashData(refreshToken);
		await this.usersService.update(userId, {
			refreshToken: hashedRefreshToken
		});
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
	
			return tokens;
		} catch(e){
			return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: e.message || 'my error' } 
		}
	}

	async sendPasswordResetToken(email:string): Promise<object> {
		try{
			const user = await this.usersService.findByEmail(email)

			if(!user) throw new BadRequestException('Email Not Exists');
		
			const resetToken = generateRandomToken() // Generate a secure random token
			const resetTokenExpiry = new Date(Date.now() + 3600000); // Token expires in 1 hour
			await this.usersService.update(user.id, {resetToken, resetTokenExpiry})
			
			//Send the reset token to user through email 
	
			const subject = 'Password Reset'
	
			const text = `Click the following link to reset your password: https://example.com/reset?token=${resetToken}`;
	
			await this.emailService.sendMail({to:email, subject, text});
	
			return { status: HttpStatus.OK, data: {message:"Reset Token is sent successfully"} }
		} catch(e){
			return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: e.message || 'my error' } 
		}

	}

	async resetPassword(resetPasswordDto: ResetPasswordDto) : Promise<object> {
		try{
			const {email, password, resetToken} = resetPasswordDto;
		
			const user = await this.usersService.findByEmail(email)
	
			if(!user) throw new BadRequestException('Email is not exists');
	
			if(user.resetToken !== resetToken || user.resetTokenExpiry < new Date()){
				throw new BadRequestException('Token is not valid');
			}
	
			const hash = await this.hashData(password); // Hash Password
	
			this.usersService.update(user.id,{password: hash, resetToken:null, resetTokenExpiry:null}) // update password 
			// response
			return { status: HttpStatus.OK, data: {message:"Password Reset Successfully"} }
		} catch (e){
			return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: e.message || 'my error' } 
		}

	}
}
